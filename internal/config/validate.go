package config

import (
	"crypto/tls"
	"fmt"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/publicsuffix"
)

var (
	validBackendStrategies = map[string]struct{}{
		"round_robin":       {},
		"least_connections": {},
		"weighted_random":   {},
	}
	validMiddlewareTypes = map[string]struct{}{
		"jwt":              {},
		"rate_limit":       {},
		"body_limit":       {},
		"ip_filter":        {},
		"cors":             {},
		"header":           {},
		"security_headers": {},
		"api_key":          {},
		"cache":            {},
		"oauth2":           {},
		"ext_authz":        {},
	}
	validInboundTLS12CipherSuites = map[string]struct{}{
		tls.CipherSuiteName(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256):       {},
		tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256):         {},
		tls.CipherSuiteName(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384):       {},
		tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384):         {},
		tls.CipherSuiteName(tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256): {},
		tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256):   {},
	}
)

const maxJWKSStaleGrace = 24 * time.Hour

const maxHealthCheckBodyBytes = 1 << 20

func validateConfig(c *Config) error {
	var errs ValidationErrors

	validateListener(c.Listener, &errs)

	backendNames := validateBackends(c.Backends, &errs)
	validateHealthEndpoints(c.Listener.Health, backendNames, &errs)
	middlewareNames := validateMiddlewares(c.Middleware, &errs)
	validateRoutes(c.Routes, backendNames, middlewareNames, &errs)

	validateObservability(c.Observability, &errs)
	validateReload(c.Reload, &errs)

	return errs.Err()
}

func validateListener(listener ListenerConfig, errs *ValidationErrors) {
	if listener.HTTP.Port <= 0 && listener.HTTPS.Port <= 0 {
		errs.Addf("listener: at least one of listener.http.port or listener.https.port must be greater than 0")
	}
	if listener.HTTP.Port < 0 {
		errs.Addf("listener.http.port: must be greater than 0")
	}
	if listener.HTTPS.Port < 0 {
		errs.Addf("listener.https.port: must be greater than 0")
	}

	if listener.HTTPS.Port > 0 {
		validateTLS("listener.https.tls", listener.HTTPS.TLS, errs)
	}
	if listener.HTTP.Port > 0 && listener.HTTPS.Port > 0 {
		if strings.TrimSpace(listener.HTTP.CanonicalHost) == "" && len(listener.HTTP.RedirectAllowedHosts) == 0 {
			errs.Addf("listener.http: canonical_host or redirect_allowed_hosts is required when HTTP redirects to HTTPS")
		}
	}
	if host := strings.TrimSpace(listener.HTTP.CanonicalHost); host != "" {
		validateRedirectHost("listener.http.canonical_host", host, errs)
	}
	for i, host := range listener.HTTP.RedirectAllowedHosts {
		validateRedirectHost(fmt.Sprintf("listener.http.redirect_allowed_hosts[%d]", i), host, errs)
	}

	validatePositiveDuration("listener.timeouts.read", listener.Timeouts.Read, errs, false)
	validatePositiveDuration("listener.timeouts.write", listener.Timeouts.Write, errs, false)
	validatePositiveDuration("listener.timeouts.idle", listener.Timeouts.Idle, errs, false)
	validatePositiveDuration("listener.timeouts.read_header", listener.Timeouts.ReadHeader, errs, true)
	validatePositiveDuration("listener.timeouts.websocket_idle", listener.Timeouts.WebSocketIdle, errs, true)
	if listener.MaxConcurrentRequests < 0 {
		errs.Addf("listener.max_concurrent_requests: must be >= 0")
	}
	if listener.MaxConnectionsPerIP < 0 {
		errs.Addf("listener.max_connections_per_ip: must be >= 0")
	}
	if listener.MaxRequestBodyBytes < 0 {
		errs.Addf("listener.max_request_body_bytes: must be >= 0")
	}
	validateIPFilterEntries("listener.trusted_proxies", listener.TrustedProxies, errs)
	validateNoPublicCIDR("listener.trusted_proxies", listener.TrustedProxies, errs)
	validateIPFilterEntries("listener.admin.allowed_cidrs", listener.Admin.AllowedCIDRs, errs)
	validateAdminAccess(listener.Admin, errs)
	validateIPFilterEntries("listener.health.access.allowed_cidrs", listener.Health.Access.AllowedCIDRs, errs)
	validateNoPublicCIDR("listener.health.access.allowed_cidrs", listener.Health.Access.AllowedCIDRs, errs)
}

func validateHealthEndpoints(health HealthEndpointsConfig, backends map[string]struct{}, errs *ValidationErrors) {
	mode := strings.ToLower(strings.TrimSpace(health.Readiness.Mode))
	switch mode {
	case "", "any", "all":
		if len(health.Readiness.CriticalBackends) != 0 {
			errs.Addf("listener.health.readiness.critical_backends: valid only when mode is critical")
		}
	case "critical":
		if len(health.Readiness.CriticalBackends) == 0 {
			errs.Addf("listener.health.readiness.critical_backends: at least one backend is required when mode is critical")
		}
	default:
		errs.Addf("listener.health.readiness.mode: must be one of any, all, critical")
	}

	seen := make(map[string]struct{}, len(health.Readiness.CriticalBackends))
	for i, rawName := range health.Readiness.CriticalBackends {
		name := strings.TrimSpace(rawName)
		if name == "" {
			errs.Addf("listener.health.readiness.critical_backends[%d]: must not be empty", i)
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			errs.Addf("listener.health.readiness.critical_backends[%d]: duplicate backend %q", i, name)
		}
		seen[name] = struct{}{}
		if _, ok := backends[name]; !ok {
			errs.Addf("listener.health.readiness.critical_backends[%d]: unknown backend %q", i, name)
		}
	}
}

func validateAdminAccess(admin AdminConfig, errs *ValidationErrors) {
	if strings.TrimSpace(admin.TokenEnv) != "" || strings.TrimSpace(admin.TokenFile) != "" {
		return
	}
	for _, entry := range admin.AllowedCIDRs {
		if !isLoopbackOnlyCIDR(entry) {
			errs.Addf("listener.admin: token_env or token_file is required when allowed_cidrs extends beyond loopback")
			return
		}
	}
}

func isLoopbackOnlyCIDR(entry string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return true
	}
	if ip := net.ParseIP(entry); ip != nil {
		return ip.IsLoopback()
	}
	ip, network, err := net.ParseCIDR(entry)
	if err != nil || !ip.IsLoopback() {
		return false
	}
	ones, bits := network.Mask.Size()
	if bits == 32 {
		// 127.0.0.0/8 is the widest IPv4 loopback range.
		return ip.To4() != nil && ip.To4()[0] == 127 && ones >= 8
	}
	// ::1 is the only IPv6 loopback address.
	return ones == 128
}

func validateTLS(prefix string, tls TLSConfig, errs *ValidationErrors) {
	mode := strings.ToLower(strings.TrimSpace(tls.Mode))
	if mode == "" {
		mode = "manual"
	}
	switch mode {
	case "manual":
		if strings.TrimSpace(tls.CertFile) == "" {
			errs.Addf("%s.cert_file: required for mode manual", prefix)
		}
		if strings.TrimSpace(tls.KeyFile) == "" {
			errs.Addf("%s.key_file: required for mode manual", prefix)
		}
		validateTLSCertificates(prefix, tls.Certificates, errs)
	case "auto":
		if len(tls.Certificates) != 0 {
			errs.Addf("%s.certificates: supported only for mode manual", prefix)
		}
		if len(tls.Domains) == 0 {
			errs.Addf("%s.domains: at least one domain is required for mode auto", prefix)
		}
		for i, d := range tls.Domains {
			if strings.TrimSpace(d) == "" {
				errs.Addf("%s.domains[%d]: must not be empty", prefix, i)
			}
		}
		validateACMECache(prefix, tls, errs)
	default:
		errs.Addf("%s.mode: must be one of manual, auto", prefix)
	}

	switch strings.TrimSpace(tls.MinVersion) {
	case "", "1.2", "1.3":
	default:
		errs.Addf("%s.min_version: must be 1.2 or 1.3", prefix)
	}
	switch strings.ToLower(strings.TrimSpace(tls.ClientAuth)) {
	case "", "require", "verify_if_given", "request":
	default:
		errs.Addf("%s.client_auth: must be one of require, verify_if_given, request", prefix)
	}
	if strings.TrimSpace(tls.ClientAuth) != "" && strings.TrimSpace(tls.ClientCAFile) == "" {
		errs.Addf("%s.client_auth: requires client_ca_file to be set", prefix)
	}
	seenCipher := make(map[string]struct{}, len(tls.CipherSuites))
	for i, rawSuite := range tls.CipherSuites {
		suite := strings.TrimSpace(rawSuite)
		if _, ok := validInboundTLS12CipherSuites[suite]; !ok {
			errs.Addf("%s.cipher_suites[%d]: unsupported or insecure TLS 1.2 cipher %q", prefix, i, rawSuite)
		}
		if _, duplicate := seenCipher[suite]; duplicate {
			errs.Addf("%s.cipher_suites[%d]: duplicate cipher %q", prefix, i, rawSuite)
		}
		seenCipher[suite] = struct{}{}
	}
	if strings.TrimSpace(tls.MinVersion) == "1.3" && len(tls.CipherSuites) != 0 {
		errs.Addf("%s.cipher_suites: cannot be configured when min_version is 1.3", prefix)
	}
}

func validateACMECache(prefix string, tls TLSConfig, errs *ValidationErrors) {
	cache := tls.ACMECache
	if namespace := strings.TrimSpace(cache.Namespace); namespace != "" {
		valid := len(namespace) <= 64
		for _, r := range namespace {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
				!(r >= '0' && r <= '9') && r != '.' && r != '_' && r != '-' {
				valid = false
				break
			}
		}
		if !valid {
			errs.Addf("%s.acme_cache.namespace: must be at most 64 characters using only letters, digits, dot, underscore, or hyphen", prefix)
		}
	}
	backend := strings.ToLower(strings.TrimSpace(cache.Backend))
	legacyDir := strings.TrimSpace(tls.ACMECacheDir)
	directory := strings.TrimSpace(cache.Directory)
	if backend == "" {
		if legacyDir != "" || directory != "" {
			backend = "filesystem"
		}
	}
	switch backend {
	case "filesystem":
		if directory == "" && legacyDir == "" {
			errs.Addf("%s.acme_cache.directory: required for filesystem backend", prefix)
		}
		if strings.TrimSpace(cache.RedisURL) != "" || strings.TrimSpace(cache.RedisURLEnv) != "" || strings.TrimSpace(cache.RedisURLFile) != "" {
			errs.Addf("%s.acme_cache: redis URL fields are invalid for filesystem backend", prefix)
		}
		if tls.Distributed {
			errs.Addf("%s.distributed: requires acme_cache.backend redis", prefix)
		}
		if tls.Replicas > 1 {
			errs.Addf("%s.replicas: multiple replicas require distributed: true and acme_cache.backend redis", prefix)
		}
	case "redis":
		if strings.TrimSpace(cache.RedisURL) == "" && strings.TrimSpace(cache.RedisURLEnv) == "" && strings.TrimSpace(cache.RedisURLFile) == "" {
			errs.Addf("%s.acme_cache: redis_url, redis_url_env, or redis_url_file is required for redis backend", prefix)
		}
		if rawURL := strings.TrimSpace(cache.RedisURL); rawURL != "" {
			parsed, err := url.Parse(rawURL)
			if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Host == "" {
				errs.Addf("%s.acme_cache.redis_url: must be a valid redis:// or rediss:// URL", prefix)
			}
		}
		if directory != "" || legacyDir != "" {
			errs.Addf("%s.acme_cache: filesystem directory is invalid for redis backend", prefix)
		}
		if !tls.Distributed {
			errs.Addf("%s.distributed: must be true for acme_cache.backend redis", prefix)
		}
	default:
		errs.Addf("%s.acme_cache.backend: must be one of filesystem, redis", prefix)
	}
	if tls.Replicas < 0 {
		errs.Addf("%s.replicas: must not be negative", prefix)
	}
	if cache.OperationTimeout < 0 {
		errs.Addf("%s.acme_cache.operation_timeout: must be greater than 0", prefix)
	}
	if cache.LockWaitTimeout < 0 {
		errs.Addf("%s.acme_cache.lock_wait_timeout: must be greater than 0", prefix)
	}
	if cache.LockTTL < 0 {
		errs.Addf("%s.acme_cache.lock_ttl: must be greater than 0", prefix)
	}
	if cache.LockRenewInterval < 0 {
		errs.Addf("%s.acme_cache.lock_renew_interval: must be greater than 0", prefix)
	}
	lockTTL := cache.LockTTL
	if lockTTL == 0 {
		lockTTL = 2 * time.Minute
	}
	renew := cache.LockRenewInterval
	if renew == 0 {
		renew = lockTTL / 3
	}
	if renew >= lockTTL {
		errs.Addf("%s.acme_cache.lock_renew_interval: must be less than lock_ttl", prefix)
	}
}

func validateTLSCertificates(prefix string, certificates []TLSCertificateConfig, errs *ValidationErrors) {
	seen := make(map[string]int)
	for i, cert := range certificates {
		field := fmt.Sprintf("%s.certificates[%d]", prefix, i)
		if strings.TrimSpace(cert.CertFile) == "" {
			errs.Addf("%s.cert_file: required", field)
		}
		if strings.TrimSpace(cert.KeyFile) == "" {
			errs.Addf("%s.key_file: required", field)
		}
		if len(cert.Hosts) == 0 {
			errs.Addf("%s.hosts: at least one host is required", field)
		}
		for j, rawHost := range cert.Hosts {
			hostField := fmt.Sprintf("%s.hosts[%d]", field, j)
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawHost), "."))
			if err := validateTLSServerName(host); err != nil {
				errs.Addf("%s: %v", hostField, err)
				continue
			}
			if previous, ok := seen[host]; ok {
				errs.Addf("%s: duplicate host %q (already configured by certificates[%d])", hostField, rawHost, previous)
				continue
			}
			seen[host] = i
		}
	}
}

func validateTLSServerName(host string) error {
	if host == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.ContainsAny(host, "/\\@?#: \t\r\n") {
		return fmt.Errorf("must be a DNS hostname without scheme, path, or port")
	}
	if strings.Contains(host, "*") {
		if !strings.HasPrefix(host, "*.") || strings.Count(host, "*") != 1 {
			return fmt.Errorf("wildcard must be the complete left-most label")
		}
		// Requiring at least two labels after the wildcard rejects broad values
		// such as *.com while preserving the common *.example.com form.
		suffix := strings.TrimPrefix(host, "*.")
		if len(strings.Split(suffix, ".")) < 2 {
			return fmt.Errorf("wildcard must be below a registrable-style domain")
		}
		if public, _ := publicsuffix.PublicSuffix(suffix); public == suffix {
			return fmt.Errorf("wildcard must not target a public suffix")
		}
		host = suffix
	}
	if len(host) > 253 {
		return fmt.Errorf("must be a valid DNS hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("must be a valid DNS hostname")
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return fmt.Errorf("must be a valid DNS hostname")
			}
		}
	}
	return nil
}

func validateRoutes(routes []RouteConfig, backendNames, middlewareNames map[string]struct{}, errs *ValidationErrors) {
	seen := make(map[string]struct{}, len(routes))

	for i, route := range routes {
		prefix := fmt.Sprintf("routes[%d]", i)
		if route.Name == "" {
			errs.Addf("%s.name: required", prefix)
		} else {
			if _, ok := seen[route.Name]; ok {
				errs.Addf("%s.name: duplicate value %q", prefix, route.Name)
			}
			seen[route.Name] = struct{}{}
		}

		path := strings.TrimSpace(route.Match.Path)
		pathPrefix := strings.TrimSpace(route.Match.PathPrefix)
		switch {
		case path == "" && pathPrefix == "":
			errs.Addf("%s.match: exactly one of path or path_prefix is required", prefix)
		case path != "" && pathPrefix != "":
			errs.Addf("%s.match: path and path_prefix are mutually exclusive", prefix)
		}
		if len(route.Match.Methods) == 0 {
			errs.Addf("%s.match.methods: must not be empty", prefix)
		}
		for j, method := range route.Match.Methods {
			if strings.TrimSpace(method) == "" {
				errs.Addf("%s.match.methods[%d]: must not be empty", prefix, j)
			}
		}
		for j, host := range route.Match.Hosts {
			if strings.TrimSpace(host) == "" {
				errs.Addf("%s.match.hosts[%d]: must not be empty", prefix, j)
			}
		}
		for name := range route.Match.Headers {
			if strings.TrimSpace(name) == "" {
				errs.Addf("%s.match.headers: header name must not be empty", prefix)
			}
		}
		for name := range route.Match.Query {
			if strings.TrimSpace(name) == "" {
				errs.Addf("%s.match.query: parameter name must not be empty", prefix)
			}
		}

		if route.Timeout < 0 {
			errs.Addf("%s.timeout: must be >= 0", prefix)
		}
		if route.MaxBodyBytes < 0 {
			errs.Addf("%s.max_body_bytes: must be >= 0", prefix)
		}
		if route.StripPrefix != "" && !strings.HasPrefix(route.StripPrefix, "/") {
			errs.Addf("%s.strip_prefix: must start with /", prefix)
		}
		if strings.TrimSpace(route.Rewrite.Pattern) != "" {
			if _, err := regexp.Compile(route.Rewrite.Pattern); err != nil {
				errs.Addf("%s.rewrite.pattern: invalid regular expression: %v", prefix, err)
			}
		}

		if route.Backend == "" {
			errs.Addf("%s.backend: required", prefix)
		} else if _, ok := backendNames[route.Backend]; !ok {
			errs.Addf("%s.backend: unknown backend %q", prefix, route.Backend)
		}

		for j, name := range route.Middleware {
			if _, ok := middlewareNames[name]; !ok {
				errs.Addf("%s.middleware[%d]: unknown middleware %q", prefix, j, name)
			}
		}
	}
}

func validateBackends(backends []BackendConfig, errs *ValidationErrors) map[string]struct{} {
	seen := make(map[string]struct{}, len(backends))

	for i, backend := range backends {
		prefix := fmt.Sprintf("backends[%d]", i)

		if backend.Name == "" {
			errs.Addf("%s.name: required", prefix)
		} else {
			if _, ok := seen[backend.Name]; ok {
				errs.Addf("%s.name: duplicate value %q", prefix, backend.Name)
			}
			seen[backend.Name] = struct{}{}
		}

		if _, ok := validBackendStrategies[backend.Strategy]; !ok {
			errs.Addf("%s.strategy: must be one of round_robin, least_connections", prefix)
		}

		switch strings.ToLower(strings.TrimSpace(backend.Protocol)) {
		case "", "http1", "h2c":
		default:
			errs.Addf("%s.protocol: must be one of http1, h2c", prefix)
		}
		// h2c is cleartext HTTP/2; outbound TLS to the backend is contradictory.
		if strings.EqualFold(strings.TrimSpace(backend.Protocol), "h2c") && hasBackendTLS(backend.TLS) {
			errs.Addf("%s.protocol: h2c (cleartext) cannot be combined with tls", prefix)
		}

		if len(backend.Instances) == 0 {
			errs.Addf("%s.instances: must contain at least one instance", prefix)
		}

		validatePositiveDuration(prefix+".health_check.interval", backend.HealthCheck.Interval, errs, true)
		validatePositiveDuration(prefix+".health_check.timeout", backend.HealthCheck.Timeout, errs, true)
		validateHealthCheck(prefix+".health_check", backend.HealthCheck, errs)
		validateOutlierDetection(prefix+".outlier_detection", backend.OutlierDetection, errs)

		cb := backend.CircuitBreaker
		if cb.Threshold < 0 {
			errs.Addf("%s.circuit_breaker.threshold: must be >= 0", prefix)
		}
		if cb.Threshold > 0 && cb.Timeout < 0 {
			errs.Addf("%s.circuit_breaker.timeout: must be >= 0", prefix)
		}

		validateRetry(prefix+".retry", backend.Retry, errs)
		validateBackendTLS(prefix+".tls", backend.TLS, errs)
		if backend.Bulkhead.MaxConcurrent < 0 {
			errs.Addf("%s.bulkhead.max_concurrent: must be >= 0", prefix)
		}

		for j, instance := range backend.Instances {
			if instance.URL == "" {
				errs.Addf("%s.instances[%d].url: required", prefix, j)
				continue
			}
			parsed, err := url.Parse(instance.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				errs.Addf("%s.instances[%d].url: invalid URL %q", prefix, j, instance.URL)
				continue
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				errs.Addf("%s.instances[%d].url: scheme must be http or https", prefix, j)
			}
			if instance.Weight < 0 {
				errs.Addf("%s.instances[%d].weight: must be >= 0", prefix, j)
			}
		}
	}

	return seen
}

func validateHealthCheck(prefix string, h HealthCheckConfig, errs *ValidationErrors) {
	if h.Path == "" && h.Interval == 0 {
		return
	}
	if !strings.HasPrefix(h.Path, "/") {
		errs.Addf("%s.path: must start with /", prefix)
	}
	method := strings.ToUpper(strings.TrimSpace(h.Method))
	switch method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		errs.Addf("%s.method: must be one of GET, HEAD, OPTIONS", prefix)
	}
	policies := 0
	if h.ExpectedStatus.Exact != 0 {
		policies++
		if h.ExpectedStatus.Exact < 100 || h.ExpectedStatus.Exact > 599 {
			errs.Addf("%s.expected_status.exact: must be a valid HTTP status code", prefix)
		}
	}
	if len(h.ExpectedStatus.Range) != 0 {
		policies++
		if len(h.ExpectedStatus.Range) != 2 ||
			h.ExpectedStatus.Range[0] < 100 || h.ExpectedStatus.Range[1] > 599 ||
			h.ExpectedStatus.Range[0] > h.ExpectedStatus.Range[1] {
			errs.Addf("%s.expected_status.range: must contain [minimum, maximum] HTTP status codes", prefix)
		}
	}
	if len(h.ExpectedStatus.List) != 0 {
		policies++
		seen := make(map[int]struct{}, len(h.ExpectedStatus.List))
		for i, status := range h.ExpectedStatus.List {
			if status < 100 || status > 599 {
				errs.Addf("%s.expected_status.list[%d]: must be a valid HTTP status code", prefix, i)
			}
			if _, ok := seen[status]; ok {
				errs.Addf("%s.expected_status.list[%d]: duplicate status %d", prefix, i, status)
			}
			seen[status] = struct{}{}
		}
	}
	if policies > 1 {
		errs.Addf("%s.expected_status: exactly one of exact, range, or list may be set", prefix)
	}
	for name, value := range h.Headers {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t\r\n:") {
			errs.Addf("%s.headers: invalid header name %q", prefix, name)
		}
		if hasUnsafeHeaderValue(value) {
			errs.Addf("%s.headers.%s: must not contain control characters", prefix, name)
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
			"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			errs.Addf("%s.headers.%s: hop-by-hop headers are not allowed", prefix, name)
		}
	}
	matchers := 0
	for _, value := range []string{h.Body.Exact, h.Body.Contains, h.Body.Regex} {
		if value != "" {
			matchers++
		}
	}
	if matchers > 1 {
		errs.Addf("%s.body: exactly one of exact, contains, or regex may be set", prefix)
	}
	if h.Body.Regex != "" {
		if _, err := regexp.Compile(h.Body.Regex); err != nil {
			errs.Addf("%s.body.regex: invalid RE2 regular expression: %v", prefix, err)
		}
	}
	if h.MaxBodyBytes < 0 || h.MaxBodyBytes > maxHealthCheckBodyBytes {
		errs.Addf("%s.max_body_bytes: must be between 0 and %d", prefix, maxHealthCheckBodyBytes)
	}
}

func validateOutlierDetection(prefix string, o OutlierDetectionConfig, errs *ValidationErrors) {
	if o.ConsecutiveFailures < 0 {
		errs.Addf("%s.consecutive_failures: must be >= 0", prefix)
	}
	if o.FailureRatePercent < 0 || o.FailureRatePercent > 100 {
		errs.Addf("%s.failure_rate_percent: must be between 0 and 100", prefix)
	}
	if o.MinimumVolume < 0 {
		errs.Addf("%s.minimum_volume: must be >= 0", prefix)
	}
	if o.Window < 0 {
		errs.Addf("%s.window: must be >= 0", prefix)
	}
	if o.BaseEjectionDuration < 0 || o.MaxEjectionDuration < 0 {
		errs.Addf("%s: ejection durations must be >= 0", prefix)
	}
	if o.MaxEjectionDuration > 0 && o.BaseEjectionDuration > o.MaxEjectionDuration {
		errs.Addf("%s.max_ejection_duration: must be >= base_ejection_duration", prefix)
	}
	if o.MaxEjectionPercent < 0 || o.MaxEjectionPercent > 100 {
		errs.Addf("%s.max_ejection_percent: must be between 0 and 100", prefix)
	}
	if o.FailureRatePercent > 0 && o.MinimumVolume == 0 {
		errs.Addf("%s.minimum_volume: must be > 0 when failure_rate_percent is set", prefix)
	}
}

func validateMiddlewares(middlewares []MiddlewareConfig, errs *ValidationErrors) map[string]struct{} {
	seen := make(map[string]struct{}, len(middlewares))

	for i, middleware := range middlewares {
		prefix := fmt.Sprintf("middleware[%d]", i)

		if middleware.Name == "" {
			errs.Addf("%s.name: required", prefix)
		} else {
			if _, ok := seen[middleware.Name]; ok {
				errs.Addf("%s.name: duplicate value %q", prefix, middleware.Name)
			}
			seen[middleware.Name] = struct{}{}
		}

		if _, ok := validMiddlewareTypes[middleware.Type]; !ok {
			errs.Addf("%s.type: must be one of jwt, rate_limit, body_limit, ip_filter, cors, header, security_headers, api_key, cache, oauth2, ext_authz", prefix)
		}

		if middleware.Type == "jwt" {
			validateJWTMiddleware(prefix+".config", middleware.Config, errs)
		}
		if middleware.Type == "rate_limit" {
			if middleware.Config.Strategy != "sliding_window" {
				errs.Addf("%s.config.strategy: only sliding_window is supported in this phase", prefix)
			}
			if middleware.Config.Limit <= 0 {
				errs.Addf("%s.config.limit: must be greater than 0", prefix)
			}
			if middleware.Config.Window <= 0 {
				errs.Addf("%s.config.window: must be greater than 0", prefix)
			}
			switch middleware.Config.By {
			case "ip", "route", "api_key":
			default:
				errs.Addf("%s.config.by: must be one of ip, route, api_key", prefix)
			}
			store := strings.ToLower(strings.TrimSpace(middleware.Config.RateLimitStore))
			switch store {
			case "", "memory", "redis":
			default:
				errs.Addf("%s.config.store: must be one of memory, redis", prefix)
			}
			if store != "redis" {
				if middleware.Config.MemoryMaxBuckets < 0 {
					errs.Addf("%s.config.memory_max_buckets: must be greater than 0", prefix)
				}
				if middleware.Config.MemoryBucketTTL < 0 {
					errs.Addf("%s.config.memory_bucket_ttl: must be greater than 0", prefix)
				}
				if middleware.Config.MemoryCleanupInterval < 0 {
					errs.Addf("%s.config.memory_cleanup_interval: must be greater than 0", prefix)
				}
				if middleware.Config.MemoryBucketTTL > 0 &&
					middleware.Config.MemoryBucketTTL < middleware.Config.Window {
					errs.Addf("%s.config.memory_bucket_ttl: must be at least config.window", prefix)
				}
			}
			if store == "redis" {
				hasURL := strings.TrimSpace(middleware.Config.RedisURL) != ""
				hasURLEnv := strings.TrimSpace(middleware.Config.RedisURLEnv) != ""
				hasURLFile := strings.TrimSpace(middleware.Config.RedisURLFile) != ""
				if !hasURL && !hasURLEnv && !hasURLFile {
					errs.Addf("%s.config: redis_url, redis_url_env or redis_url_file is required when store is redis", prefix)
				}
			}
		}
		if middleware.Type == "cors" {
			if len(middleware.Config.AllowedOrigins) == 0 {
				errs.Addf("%s.config.allowed_origins: must not be empty", prefix)
			}
			if len(middleware.Config.AllowedMethods) == 0 {
				errs.Addf("%s.config.allowed_methods: must not be empty", prefix)
			}
		}
		if middleware.Type == "body_limit" {
			if middleware.Config.MaxBytes <= 0 {
				errs.Addf("%s.config.max_bytes: must be greater than 0", prefix)
			}
		}
		if middleware.Type == "ip_filter" {
			if len(middleware.Config.Allow) == 0 && len(middleware.Config.Deny) == 0 {
				errs.Addf("%s.config: at least one of allow or deny must be provided", prefix)
			}
			validateIPFilterEntries(prefix+".config.allow", middleware.Config.Allow, errs)
			validateIPFilterEntries(prefix+".config.deny", middleware.Config.Deny, errs)
		}
		if middleware.Type == "header" {
			if len(middleware.Config.RequestSet) == 0 &&
				len(middleware.Config.RequestDel) == 0 &&
				len(middleware.Config.ResponseSet) == 0 &&
				len(middleware.Config.ResponseDel) == 0 {
				errs.Addf("%s.config: at least one of request_set, request_del, response_set, response_del must be provided", prefix)
			}
		}
		if middleware.Type == "security_headers" {
			validateSecurityHeadersMiddleware(prefix+".config", middleware.Config, errs)
		}
		if middleware.Type == "api_key" {
			validateAPIKeyMiddleware(prefix+".config", middleware.Config, errs)
		}
		if middleware.Type == "cache" {
			validateCacheMiddleware(prefix+".config", middleware.Config, errs)
		}
		if middleware.Type == "oauth2" {
			validateOAuth2Middleware(prefix+".config", middleware.Config, errs)
		}
		if middleware.Type == "ext_authz" {
			validateExtAuthzMiddleware(prefix+".config", middleware.Config, errs)
		}
	}

	return seen
}

func validateRedirectHost(field, value string, errs *ValidationErrors) {
	host := strings.TrimSpace(value)
	if host == "" {
		errs.Addf("%s: must not be empty", field)
		return
	}
	if strings.ContainsAny(host, "/\\@?# \t\r\n") {
		errs.Addf("%s: must be a hostname or IP address without scheme, path, or port", field)
		return
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if net.ParseIP(host) != nil {
		return
	}
	if strings.Contains(host, ":") || len(host) > 253 {
		errs.Addf("%s: must be a valid hostname or IP address without a port", field)
		return
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			errs.Addf("%s: must be a valid hostname or IP address without a port", field)
			return
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
				errs.Addf("%s: must be a valid hostname or IP address without a port", field)
				return
			}
		}
	}
}

func validateSecurityHeadersMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	switch strings.ToLower(strings.TrimSpace(cfg.SecurityHeadersPreset)) {
	case "", "secure", "strict":
	default:
		errs.Addf("%s.preset: must be one of secure, strict", prefix)
	}

	values := map[string]string{
		"strict_transport_security": cfg.StrictTransportSecurity,
		"content_security_policy":   cfg.ContentSecurityPolicy,
		"x_frame_options":           cfg.XFrameOptions,
		"x_content_type_options":    cfg.XContentTypeOptions,
		"referrer_policy":           cfg.ReferrerPolicy,
		"permissions_policy":        cfg.PermissionsPolicy,
	}
	hasExplicit := false
	for name, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			hasExplicit = true
		}
		if hasUnsafeHeaderValue(value) {
			errs.Addf("%s.%s: must not contain control characters", prefix, name)
		}
	}
	if strings.TrimSpace(cfg.SecurityHeadersPreset) == "" && !hasExplicit {
		errs.Addf("%s: preset or at least one explicit security header is required", prefix)
	}

	validateHSTS(prefix+".strict_transport_security", cfg.StrictTransportSecurity, errs)
	validateCSP(prefix+".content_security_policy", cfg.ContentSecurityPolicy, errs)
	if value := strings.ToUpper(strings.TrimSpace(cfg.XFrameOptions)); value != "" && value != "OFF" && value != "DENY" && value != "SAMEORIGIN" {
		errs.Addf("%s.x_frame_options: must be DENY, SAMEORIGIN, or off", prefix)
	}
	if value := strings.ToLower(strings.TrimSpace(cfg.XContentTypeOptions)); value != "" && value != "off" && value != "nosniff" {
		errs.Addf("%s.x_content_type_options: must be nosniff or off", prefix)
	}
	if value := strings.ToLower(strings.TrimSpace(cfg.ReferrerPolicy)); value == "unsafe-url" {
		errs.Addf("%s.referrer_policy: unsafe-url is not allowed", prefix)
	} else if value != "" && value != "off" && !validReferrerPolicy(value) {
		errs.Addf("%s.referrer_policy: must contain only recognized safe policies or off", prefix)
	}
	if value := strings.TrimSpace(cfg.PermissionsPolicy); value != "" && !isHeaderOff(value) {
		validatePermissionsPolicy(prefix+".permissions_policy", value, errs)
	}

	csp := effectiveSecurityHeader(cfg.SecurityHeadersPreset, cfg.ContentSecurityPolicy, "default-src 'self'; object-src 'none'; base-uri 'self'", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	xfo := effectiveSecurityHeader(cfg.SecurityHeadersPreset, cfg.XFrameOptions, "DENY", "off")
	if containsCSPDirective(csp, "frame-ancestors") && !isHeaderOff(xfo) {
		errs.Addf("%s: x_frame_options and content_security_policy frame-ancestors cannot both be enabled", prefix)
	}
	effective := []string{
		effectiveSecurityHeader(cfg.SecurityHeadersPreset, cfg.StrictTransportSecurity, "max-age=31536000; includeSubDomains", "max-age=63072000; includeSubDomains; preload"),
		csp,
		xfo,
		effectiveSecurityHeader(cfg.SecurityHeadersPreset, cfg.XContentTypeOptions, "nosniff", "nosniff"),
		effectiveSecurityHeader(cfg.SecurityHeadersPreset, cfg.ReferrerPolicy, "no-referrer", "no-referrer"),
		effectiveSecurityHeader(cfg.SecurityHeadersPreset, cfg.PermissionsPolicy, "camera=(), microphone=(), geolocation=()", "camera=(), microphone=(), geolocation=()"),
	}
	enabled := false
	for _, value := range effective {
		if strings.TrimSpace(value) != "" && !isHeaderOff(value) {
			enabled = true
			break
		}
	}
	if !enabled {
		errs.Addf("%s: at least one security header must remain enabled", prefix)
	}
}

func validateHSTS(field, value string, errs *ValidationErrors) {
	value = strings.TrimSpace(value)
	if value == "" || isHeaderOff(value) {
		return
	}
	var maxAge int64 = -1
	seenMaxAge := false
	includeSubdomains := false
	preload := false
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lower, "max-age="):
			parsed, err := strconv.ParseInt(strings.TrimPrefix(lower, "max-age="), 10, 64)
			if err != nil || parsed < 0 || seenMaxAge {
				errs.Addf("%s: max-age must be a non-negative integer", field)
				return
			}
			maxAge = parsed
			seenMaxAge = true
		case lower == "includesubdomains":
			includeSubdomains = true
		case lower == "preload":
			preload = true
		default:
			errs.Addf("%s: unsupported HSTS directive %q", field, part)
			return
		}
	}
	if maxAge < 0 {
		errs.Addf("%s: max-age is required", field)
	}
	if preload && (!includeSubdomains || maxAge < 31536000) {
		errs.Addf("%s: preload requires includeSubDomains and max-age >= 31536000", field)
	}
}

func validReferrerPolicy(value string) bool {
	valid := map[string]struct{}{
		"no-referrer":                     {},
		"no-referrer-when-downgrade":      {},
		"origin":                          {},
		"origin-when-cross-origin":        {},
		"same-origin":                     {},
		"strict-origin":                   {},
		"strict-origin-when-cross-origin": {},
	}
	for _, policy := range strings.Split(value, ",") {
		if _, ok := valid[strings.TrimSpace(policy)]; !ok {
			return false
		}
	}
	return true
}

func validatePermissionsPolicy(field, value string, errs *ValidationErrors) {
	if strings.Contains(value, "*") {
		errs.Addf("%s: wildcard permissions are not allowed", field)
		return
	}
	for _, directive := range strings.Split(value, ",") {
		directive = strings.TrimSpace(directive)
		eq := strings.IndexByte(directive, '=')
		if eq <= 0 || !strings.HasPrefix(strings.TrimSpace(directive[eq+1:]), "(") || !strings.HasSuffix(strings.TrimSpace(directive[eq+1:]), ")") {
			errs.Addf("%s: each directive must use feature=(allowlist) syntax", field)
			return
		}
		feature := strings.TrimSpace(directive[:eq])
		for _, r := range feature {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				errs.Addf("%s: invalid feature name %q", field, feature)
				return
			}
		}
	}
}

func validateCSP(field, value string, errs *ValidationErrors) {
	value = strings.TrimSpace(value)
	if value == "" || isHeaderOff(value) {
		return
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "'unsafe-inline'") || strings.Contains(lower, "'unsafe-eval'") {
		errs.Addf("%s: unsafe-inline and unsafe-eval are not allowed", field)
	}
	for _, directive := range strings.Split(value, ";") {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(directive)))
		if len(fields) > 1 && fields[0] == "frame-ancestors" {
			for _, source := range fields[1:] {
				if source == "*" || strings.HasPrefix(source, "http:") || strings.HasPrefix(source, "data:") {
					errs.Addf("%s: insecure frame-ancestors source %q is not allowed", field, source)
				}
			}
		}
	}
}

func effectiveSecurityHeader(preset, override, secure, strict string) string {
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}
	if strings.EqualFold(strings.TrimSpace(preset), "strict") {
		return strict
	}
	if strings.EqualFold(strings.TrimSpace(preset), "secure") {
		return secure
	}
	return ""
}

func containsCSPDirective(value, directive string) bool {
	if isHeaderOff(value) {
		return false
	}
	for _, part := range strings.Split(value, ";") {
		fields := strings.Fields(part)
		if len(fields) > 0 && strings.EqualFold(fields[0], directive) {
			return true
		}
	}
	return false
}

func isHeaderOff(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "off")
}

func hasUnsafeHeaderValue(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validateCacheMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	if cfg.TTL < 0 {
		errs.Addf("%s.ttl: must be >= 0", prefix)
	}
	if cfg.MaxObjectBytes < 0 {
		errs.Addf("%s.max_object_bytes: must be >= 0", prefix)
	}
	if cfg.MaxEntries < 0 {
		errs.Addf("%s.max_entries: must be >= 0", prefix)
	}
	for i, m := range cfg.CacheMethods {
		if strings.TrimSpace(m) == "" {
			errs.Addf("%s.methods[%d]: must not be empty", prefix, i)
		}
	}
	for i, code := range cfg.CacheableStatus {
		if code < 100 || code > 599 {
			errs.Addf("%s.cacheable_status[%d]: must be a valid HTTP status code", prefix, i)
		}
	}
}

func validateOAuth2Middleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	u := strings.TrimSpace(cfg.IntrospectionURL)
	if u == "" {
		errs.Addf("%s.introspection_url: required", prefix)
	} else if parsed, err := url.Parse(u); err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		// The introspection endpoint receives bearer tokens and client
		// credentials; a plaintext URL would leak them.
		errs.Addf("%s.introspection_url: must be an https URL", prefix)
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		errs.Addf("%s.client_id: required", prefix)
	}
	if strings.TrimSpace(cfg.ClientSecretEnv) == "" && strings.TrimSpace(cfg.ClientSecretFile) == "" {
		errs.Addf("%s: client_secret_env or client_secret_file is required", prefix)
	}
	if cfg.IntrospectionCacheTTL < 0 {
		errs.Addf("%s.cache_ttl: must be >= 0", prefix)
	}
}

func validateExtAuthzMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	u := strings.TrimSpace(cfg.AuthzURL)
	if u == "" {
		errs.Addf("%s.authz_url: required", prefix)
	} else if parsed, err := url.Parse(u); err != nil || !strings.EqualFold(parsed.Scheme, "https") && !(strings.EqualFold(parsed.Scheme, "http") && cfg.AuthzAllowInsecureHTTP) {
		errs.Addf("%s.authz_url: must be https unless allow_insecure_http is set", prefix)
	}
	if cfg.AuthzTimeout < 0 {
		errs.Addf("%s.authz_timeout: must be >= 0", prefix)
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.AuthzMethod))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodHead {
		errs.Addf("%s.authz_method: must be GET, POST, or HEAD", prefix)
	}
	body := strings.ToLower(strings.TrimSpace(cfg.AuthzBody))
	if body == "" {
		body = "none"
	}
	if body != "none" && body != "original" && body != "metadata" {
		errs.Addf("%s.authz_body: must be none, original, or metadata", prefix)
	}
	if (body == "original" || body == "metadata") && method != http.MethodPost {
		errs.Addf("%s.authz_body: %s requires authz_method POST", prefix, body)
	}
	if cfg.AuthzMaxBodyBytes < 0 || cfg.AuthzMaxBodyBytes == math.MaxInt64 {
		errs.Addf("%s.authz_max_body_bytes: must be between 0 and %d", prefix, int64(math.MaxInt64-1))
	}
	contentType := strings.TrimSpace(cfg.AuthzContentType)
	if body == "none" && contentType != "" {
		errs.Addf("%s.authz_content_type: requires authz_body original or metadata", prefix)
	}
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			errs.Addf("%s.authz_content_type: invalid media type", prefix)
		} else if body == "metadata" && mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
			errs.Addf("%s.authz_content_type: metadata requires application/json or +json", prefix)
		}
	}
	for _, field := range []struct {
		name    string
		headers []string
	}{
		{name: "forward_headers", headers: cfg.AuthzForwardHeaders},
		{name: "copy_headers", headers: cfg.AuthzCopyHeaders},
	} {
		for _, header := range field.headers {
			header = strings.TrimSpace(header)
			if header != "" && !httpguts.ValidHeaderFieldName(header) {
				errs.Addf("%s.%s: invalid header name %q", prefix, field.name, header)
			}
		}
	}
	if cfg.FailOpen && !cfg.AcknowledgeExtAuthzFailOpen {
		errs.Addf("%s.acknowledge_ext_authz_fail_open: must be true when fail_open is enabled; fail_open bypasses authorization when the authorizer is unavailable", prefix)
	}
}

// hasBackendTLS reports whether any outbound backend TLS field is set.
func hasBackendTLS(cfg BackendTLSConfig) bool {
	return strings.TrimSpace(cfg.CertFile) != "" ||
		strings.TrimSpace(cfg.KeyFile) != "" ||
		strings.TrimSpace(cfg.CAFile) != "" ||
		cfg.InsecureSkipVerify
}

func validateBackendTLS(prefix string, cfg BackendTLSConfig, errs *ValidationErrors) {
	hasCert := strings.TrimSpace(cfg.CertFile) != ""
	hasKey := strings.TrimSpace(cfg.KeyFile) != ""
	if hasCert && !hasKey {
		errs.Addf("%s.key_file: required when cert_file is set", prefix)
	}
	if hasKey && !hasCert {
		errs.Addf("%s.cert_file: required when key_file is set", prefix)
	}
	if cfg.InsecureSkipVerify && !cfg.AcknowledgeInsecureSkipVerify {
		errs.Addf("%s.acknowledge_insecure_skip_verify: must be true when insecure_skip_verify is enabled", prefix)
	}
}

func validateAPIKeyMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	hasEnv := strings.TrimSpace(cfg.KeysEnv) != ""
	hasFile := strings.TrimSpace(cfg.KeysFile) != ""
	if !hasEnv && !hasFile {
		errs.Addf("%s: at least one of keys_env or keys_file is required", prefix)
	}
	if strings.TrimSpace(cfg.KeyQuery) != "" && !cfg.AcknowledgeAPIKeyInQuery {
		errs.Addf("%s.acknowledge_api_key_in_query: must be true when key_query is set; query-string API keys can leak through logs, caches, and referrers", prefix)
	}
}

func validateIPFilterEntries(field string, entries []string, errs *ValidationErrors) {
	for i, entry := range entries {
		value := strings.TrimSpace(entry)
		if value == "" {
			errs.Addf("%s[%d]: must not be empty", field, i)
			continue
		}

		if ip := net.ParseIP(value); ip != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err == nil {
			continue
		}
		errs.Addf("%s[%d]: must be a valid IP or CIDR", field, i)
	}
}

func validateJWTMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	alg := strings.ToLower(strings.TrimSpace(cfg.Algorithm))
	if alg == "" {
		alg = "hs256"
	}

	switch alg {
	case "hs256":
		if strings.TrimSpace(cfg.SecretEnv) == "" && strings.TrimSpace(cfg.SecretFile) == "" {
			errs.Addf("%s: secret_env or secret_file is required for algorithm hs256", prefix)
		}
	case "rs256":
		hasFile := strings.TrimSpace(cfg.PublicKeyFile) != ""
		hasJWKS := strings.TrimSpace(cfg.JWKSUrl) != ""
		hasOIDC := strings.TrimSpace(cfg.OIDCIssuer) != ""
		sources := 0
		for _, present := range []bool{hasFile, hasJWKS, hasOIDC} {
			if present {
				sources++
			}
		}
		switch {
		case sources > 1:
			errs.Addf("%s: public_key_file, jwks_url and oidc_issuer are mutually exclusive", prefix)
		case sources == 0:
			errs.Addf("%s: one of public_key_file, jwks_url or oidc_issuer is required for algorithm rs256", prefix)
		}
		if (hasJWKS || hasOIDC) && cfg.JWKSCacheTTL < 0 {
			errs.Addf("%s.jwks_cache_ttl: must be >= 0", prefix)
		}
		if hasJWKS || hasOIDC {
			switch {
			case cfg.JWKSStaleGrace < 0:
				errs.Addf("%s.jwks_stale_grace: must be >= 0", prefix)
			case cfg.JWKSStaleGrace > maxJWKSStaleGrace:
				errs.Addf("%s.jwks_stale_grace: must be <= %s", prefix, maxJWKSStaleGrace)
			}
		}
		if hasJWKS {
			// The JWKS endpoint is the trust anchor for RS256 verification; a
			// plaintext URL is exploitable via MITM key substitution.
			if u, err := url.Parse(strings.TrimSpace(cfg.JWKSUrl)); err != nil || !strings.EqualFold(u.Scheme, "https") {
				errs.Addf("%s.jwks_url: must be an https URL", prefix)
			}
		}
		if hasOIDC {
			// Discovery + JWKS are fetched from the issuer; require https so the
			// key material cannot be substituted in transit.
			if u, err := url.Parse(strings.TrimSpace(cfg.OIDCIssuer)); err != nil || !strings.EqualFold(u.Scheme, "https") {
				errs.Addf("%s.oidc_issuer: must be an https URL", prefix)
			}
		}
		if hasJWKS || hasOIDC {
			if strings.TrimSpace(cfg.ExpectedIssuer) == "" {
				errs.Addf("%s.issuer: required for rs256 with remote JWKS or OIDC discovery", prefix)
			}
			if strings.TrimSpace(cfg.ExpectedAudience) == "" {
				errs.Addf("%s.audience: required for rs256 with remote JWKS or OIDC discovery", prefix)
			}
		}
	default:
		errs.Addf("%s.algorithm: must be one of hs256, rs256", prefix)
	}

	validateJWTClaimsToHeaders(prefix, cfg.ClaimsToHeaders, errs)
}

func validateJWTClaimsToHeaders(field string, m map[string]string, errs *ValidationErrors) {
	if len(m) == 0 {
		return
	}

	seenDest := make(map[string]struct{}, len(m))
	for claim, dest := range m {
		claim = strings.TrimSpace(claim)
		dest = strings.TrimSpace(dest)
		if claim == "" {
			errs.Addf("%s.claims_to_headers: claim name must not be empty", field)
		}
		if dest == "" {
			errs.Addf("%s.claims_to_headers: header name for claim %q must not be empty", field, claim)
		}
		if _, ok := seenDest[dest]; ok {
			errs.Addf("%s.claims_to_headers: duplicate destination header %q", field, dest)
		} else {
			seenDest[dest] = struct{}{}
		}
	}
}

func validateObservability(observability ObservabilityConfig, errs *ValidationErrors) {
	switch strings.ToLower(strings.TrimSpace(observability.Logs.Level)) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		errs.Addf("observability.logs.level: must be one of debug, info, warn, error")
	}
	switch strings.ToLower(strings.TrimSpace(observability.Logs.Format)) {
	case "", "json", "text":
	default:
		errs.Addf("observability.logs.format: must be one of json, text")
	}
	if observability.Logs.File != "" && strings.TrimSpace(observability.Logs.File) == "" {
		errs.Addf("observability.logs.file: must not be blank")
	}
	if observability.Logs.MaxSizeMB < 0 {
		errs.Addf("observability.logs.max_size_mb: must be >= 0")
	}
	if observability.Logs.MaxAgeDays < 0 {
		errs.Addf("observability.logs.max_age_days: must be >= 0")
	}
	validateIPFilterEntries("observability.prometheus.allowed_cidrs", observability.Prometheus.AllowedCIDRs, errs)
	validateNoPublicCIDR("observability.prometheus.allowed_cidrs", observability.Prometheus.AllowedCIDRs, errs)
	validateFabric(observability.Fabric, errs)
	validateTracing(observability.Tracing, errs)
}

// validateNoPublicCIDR prevents a configuration typo from trusting every
// internet peer with forwarding headers or internal operational endpoints.
func validateNoPublicCIDR(field string, entries []string, errs *ValidationErrors) {
	for i, entry := range entries {
		_, network, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones == 0 {
			errs.Addf("%s[%d]: public CIDRs (0.0.0.0/0 or ::/0) are not allowed", field, i)
		}
	}
}

func validateTracing(t TracingConfig, errs *ValidationErrors) {
	if !t.Enabled {
		return
	}
	exp := strings.ToLower(strings.TrimSpace(t.Exporter))
	switch exp {
	case "otlp_grpc", "otlp_http", "stdout", "":
	default:
		errs.Addf("observability.tracing.exporter: must be one of otlp_grpc, otlp_http, stdout")
	}
	if t.SampleRate < 0 || t.SampleRate > 1 {
		errs.Addf("observability.tracing.sample_rate: must be between 0.0 and 1.0")
	}
}

var validRetryConditions = map[string]struct{}{
	"5xx":           {},
	"network_error": {},
}

func validateRetry(prefix string, r RetryConfig, errs *ValidationErrors) {
	if r.Attempts <= 1 {
		return
	}
	if r.BackoffInit < 0 {
		errs.Addf("%s.backoff_init: must be >= 0", prefix)
	}
	if r.BackoffMax < 0 {
		errs.Addf("%s.backoff_max: must be >= 0", prefix)
	}
	if r.BackoffMax > 0 && r.BackoffInit > 0 && r.BackoffMax < r.BackoffInit {
		errs.Addf("%s.backoff_max: must be >= backoff_init", prefix)
	}
	for i, cond := range r.On {
		if _, ok := validRetryConditions[strings.ToLower(cond)]; !ok {
			errs.Addf("%s.on[%d]: must be one of 5xx, network_error", prefix, i)
		}
	}
	if r.BudgetRatio < 0 {
		errs.Addf("%s.budget_ratio: must be >= 0", prefix)
	}
	if r.BudgetTokens < 0 {
		errs.Addf("%s.budget_tokens: must be >= 0", prefix)
	}
}

func validateFabric(f FabricConfig, errs *ValidationErrors) {
	if !f.Enabled {
		return
	}
	if strings.TrimSpace(f.ServiceName) == "" {
		errs.Addf("observability.fabric.service_name: required when fabric.enabled is true")
	}
	if f.QueueSize < 0 {
		errs.Addf("observability.fabric.queue_size: must be >= 0")
	}
}

func validateReload(reload ReloadConfig, errs *ValidationErrors) {
	if !reload.Watch {
		return
	}
	if reload.Debounce <= 0 {
		errs.Addf("reload.debounce: must be > 0 when reload.watch is enabled")
	}
}

func validatePositiveDuration(field string, value time.Duration, errs *ValidationErrors, allowZero bool) {
	if value < 0 {
		errs.Addf("%s: must be greater than 0", field)
		return
	}
	if !allowZero && value == 0 {
		errs.Addf("%s: must be greater than 0", field)
	}
}
