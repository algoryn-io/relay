package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Include lists additional config files (relative to this file's directory,
	// or absolute) whose routes, backends and middleware are merged into this
	// config. Includes are loaded once (idempotent), so shared bases and cycles
	// are handled safely. Other sections (listener, observability, ...) come from
	// the top-level file.
	Include       []string            `yaml:"include"`
	Listener      ListenerConfig      `yaml:"listener"`
	Routes        []RouteConfig       `yaml:"routes"`
	Backends      []BackendConfig     `yaml:"backends"`
	Middleware    []MiddlewareConfig  `yaml:"middleware"`
	Observability ObservabilityConfig `yaml:"observability"`
	Reload        ReloadConfig        `yaml:"reload"`
}

type ListenerConfig struct {
	HTTP           HTTPConfig     `yaml:"http"`
	HTTPS          HTTPSConfig    `yaml:"https"`
	TLS            TLSConfig      `yaml:"tls"`
	Timeouts       TimeoutsConfig `yaml:"timeouts"`
	TrustedProxies []string       `yaml:"trusted_proxies"`
	// EmitForwardedHeader makes Relay generate an RFC 7239 Forwarded header
	// from normalized, Relay-owned values. Inbound Forwarded is always stripped.
	EmitForwardedHeader bool                  `yaml:"emit_forwarded_header"`
	Admin               AdminConfig           `yaml:"admin"`
	Health              HealthEndpointsConfig `yaml:"health"`
	// StripRequestHeaders lists additional inbound headers to remove at the edge
	// before any routing or proxying, on top of the always-stripped Relay-managed
	// identity headers. Use it for app-specific identity headers a backend trusts
	// (e.g. X-User-Id, X-Roles) so clients cannot spoof them.
	StripRequestHeaders []string `yaml:"strip_request_headers"`
	// MaxConcurrentRequests caps in-flight proxied requests across all routes
	// (global overload backpressure on top of per-backend bulkheads). Excess
	// requests get a fast 503. 0 means unlimited.
	MaxConcurrentRequests int `yaml:"max_concurrent_requests"`
	// MaxConnectionsPerIP caps simultaneous TCP connections from one real peer
	// IP. It is enforced before HTTP parsing, so forwarding headers and
	// TrustedProxies do not affect it. 0 disables the limit.
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip"`
	// MaxRequestBodyBytes caps request bodies for every proxied route unless
	// that route defines max_body_bytes explicitly. Zero is normalized to a
	// secure default of 10 MiB.
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes"`
}

// EndpointAccessConfig is the shared CIDR and bearer-token policy used by
// operational endpoints. Callers decide whether an empty CIDR list means public
// access (health endpoints) or loopback-only access (admin endpoints).
type EndpointAccessConfig struct {
	// AllowedCIDRs is the list of IP ranges that may call admin endpoints.
	// Defaults to loopback only (127.0.0.0/8 and ::1/128) when empty.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	// TokenEnv names an environment variable holding a bearer token. When set,
	// admin requests must present "Authorization: Bearer <token>" in addition to
	// passing the IP allowlist. Leave empty for IP-only access.
	TokenEnv string `yaml:"token_env"`
	// TokenFile reads the admin bearer token from a mounted file. Alternative to
	// token_env; token_env wins if both are set.
	TokenFile     string `yaml:"token_file"`
	ResolvedToken string `yaml:"-"`
}

// AdminConfig controls access to the /_relay/admin/* management endpoints.
type AdminConfig = EndpointAccessConfig

// HealthEndpointsConfig controls disclosure, access, and readiness semantics
// for /_relay/health and /_relay/ready.
type HealthEndpointsConfig struct {
	// Access is optional. Empty keeps the minimal health endpoints public.
	Access EndpointAccessConfig `yaml:"access"`
	// Readiness selects how backend availability is aggregated.
	Readiness ReadinessPolicyConfig `yaml:"readiness"`
}

// ReadinessPolicyConfig determines which backends must have a serving instance.
// Mode defaults to "any"; supported values are "any", "all", and "critical".
type ReadinessPolicyConfig struct {
	Mode             string   `yaml:"mode"`
	CriticalBackends []string `yaml:"critical_backends"`
}

type HTTPConfig struct {
	Port int `yaml:"port"`
	// CanonicalHost is the fixed hostname used by HTTP-to-HTTPS redirects.
	// It must not contain a port; the configured HTTPS port is applied.
	CanonicalHost string `yaml:"canonical_host"`
	// RedirectAllowedHosts restricts request Host values that may be reflected
	// into an HTTPS redirect when CanonicalHost is empty. Entries never include
	// ports and may be DNS names, IPv4 addresses, or IPv6 addresses.
	RedirectAllowedHosts []string `yaml:"redirect_allowed_hosts"`
}

type HTTPSConfig struct {
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Mode    string   `yaml:"mode"`
	Domains []string `yaml:"domains"`
	// ACMEEmail identifies the ACME account and is also part of the cache
	// namespace, preventing unrelated accounts from sharing credentials.
	ACMEEmail string `yaml:"acme_email"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	// Certificates adds SNI-specific certificate/key pairs in manual mode.
	// Hosts may be exact DNS names or a single left-most wildcard
	// (for example, "*.example.com"). CertFile/KeyFile remain the default pair.
	Certificates []TLSCertificateConfig `yaml:"certificates"`
	// ACMECacheDir is the writable, persistent cache directory used by TLS
	// mode "auto". It must be mounted in container deployments.
	ACMECacheDir string `yaml:"acme_cache_dir"`
	// ACMECache configures either a local filesystem cache or a shared Redis
	// cache with distributed issuance leases.
	ACMECache ACMECacheConfig `yaml:"acme_cache"`
	// Replicas declares how many Relay instances share this TLS configuration.
	// Values greater than one require a distributed Redis ACME cache.
	Replicas int `yaml:"replicas"`
	// Distributed acknowledges that ACME coordination is required across
	// replicas. It is accepted only with the Redis cache backend.
	Distributed bool `yaml:"distributed"`
	// MinVersion is the minimum accepted TLS version: "1.2" (default) or "1.3".
	MinVersion string `yaml:"min_version"`
	// CipherSuites optionally selects supported TLS 1.2 cipher suites by IANA
	// name. TLS 1.3 cipher suites are not configurable in Go.
	CipherSuites []string `yaml:"cipher_suites"`
	// ClientCAFile, when set, enables inbound mTLS: clients must present a
	// certificate signed by a CA in this PEM bundle.
	ClientCAFile string `yaml:"client_ca_file"`
	// ClientAuth selects the client-certificate policy when ClientCAFile is set:
	// "require" (default) verifies a cert is presented and valid; "verify_if_given"
	// verifies only when one is presented; "request" asks but does not enforce.
	ClientAuth string `yaml:"client_auth"`
}

type ACMECacheConfig struct {
	// Backend is "filesystem" (single replica) or "redis" (distributed).
	Backend string `yaml:"backend"`
	// Directory is the persistent filesystem cache location.
	Directory string `yaml:"directory"`
	// RedisURL may be supplied directly for development. Prefer RedisURLEnv or
	// RedisURLFile in production; env wins over file, which wins over this value.
	RedisURL     string `yaml:"redis_url"`
	RedisURLEnv  string `yaml:"redis_url_env"`
	RedisURLFile string `yaml:"redis_url_file"`
	// Namespace is an optional operator-controlled prefix. Relay appends a
	// deterministic account/domain scope so unrelated ACME state cannot collide.
	Namespace string `yaml:"namespace"`
	// OperationTimeout bounds individual Redis commands.
	OperationTimeout time.Duration `yaml:"operation_timeout"`
	// LockWaitTimeout bounds waiting for another replica to finish issuance.
	LockWaitTimeout time.Duration `yaml:"lock_wait_timeout"`
	// LockTTL is the lease lifetime; LockRenewInterval refreshes an owned lease.
	LockTTL           time.Duration `yaml:"lock_ttl"`
	LockRenewInterval time.Duration `yaml:"lock_renew_interval"`
}

type TLSCertificateConfig struct {
	Hosts    []string `yaml:"hosts"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
}

type TimeoutsConfig struct {
	Read  time.Duration `yaml:"read"`
	Write time.Duration `yaml:"write"`
	Idle  time.Duration `yaml:"idle"`
	// ReadHeader bounds how long reading request headers may take (Slowloris
	// mitigation). Defaults to 10s when zero.
	ReadHeader time.Duration `yaml:"read_header"`
	// WebSocketIdle closes a proxied WebSocket/upgrade tunnel after this much
	// idle time on the client connection. 0 disables it (no idle timeout).
	WebSocketIdle time.Duration `yaml:"websocket_idle"`
	ReadTimeout   time.Duration `yaml:"-"`
	WriteTimeout  time.Duration `yaml:"-"`
	IdleTimeout   time.Duration `yaml:"-"`
}

// RewriteRule rewrites the outbound request path using a regular expression
// before the request is forwarded to the backend. Pattern uses RE2 syntax;
// capture groups can be referenced as $1, $2 or ${name} in Replacement.
// Applied after strip_prefix and before the request reaches the backend.
type RewriteRule struct {
	// Pattern is a RE2 regular expression matched against the request path.
	Pattern string `yaml:"pattern"`
	// Replacement is the substitution string. Use $1/$2 or ${name} to
	// reference numbered or named capture groups from Pattern.
	Replacement string `yaml:"replacement"`
}

type RouteConfig struct {
	Name        string      `yaml:"name"`
	ID          string      `yaml:"id"`
	Match       MatchConfig `yaml:"match"`
	Middleware  []string    `yaml:"middleware"`
	Middlewares []string    `yaml:"-"`
	Backend     string      `yaml:"backend"`
	// Failover lists secondary backends tried when the primary cannot serve
	// (no healthy instances / all circuits open / bulkhead full).
	Failover RouteFailoverConfig `yaml:"-"` // set via UnmarshalYAML
	// Traffic configures canary percentage splits, sticky sessions, and async
	// request mirroring for this route.
	Traffic     RouteTrafficConfig `yaml:"-"` // set via UnmarshalYAML
	StripPrefix string             `yaml:"-"` // set via UnmarshalYAML
	Timeout     time.Duration      `yaml:"-"` // set via UnmarshalYAML
	// MaxBodyBytes caps the request body size for this route. Requests with a
	// larger body are rejected with 413. 0 means no limit.
	MaxBodyBytes int64 `yaml:"-"` // set via UnmarshalYAML
	// Rewrite applies a regex rewrite to the request path before proxying.
	// Leave Pattern empty to disable.
	Rewrite RewriteRule `yaml:"-"` // set via UnmarshalYAML
	// AddRequestHeaders injects headers into the outbound request.
	// Values of the form "${req.HEADER-NAME}" copy the named incoming header.
	// All other values are used verbatim.
	AddRequestHeaders map[string]string `yaml:"-"` // set via UnmarshalYAML
	// PropagateClientIdentity overrides the backend identity policy for this route.
	PropagateClientIdentity *ClientIdentityPropagationConfig `yaml:"-"`
}

// RouteFailoverConfig configures primary→secondary backend failover for a route.
// The route's Backend is always the primary. Secondary backends are tried in
// order when the primary cannot accept the request.
type RouteFailoverConfig struct {
	// Secondary is a single secondary backend name (shorthand for backends: [name]).
	Secondary string `yaml:"secondary"`
	// Backends is an ordered list of secondary backends. Mutually exclusive with Secondary.
	Backends []string `yaml:"backends"`
}

// RouteTrafficConfig holds optional per-route traffic policies.
type RouteTrafficConfig struct {
	Canary RouteCanaryConfig `yaml:"canary"`
	Sticky RouteStickyConfig `yaml:"sticky"`
	Mirror RouteMirrorConfig `yaml:"mirror"`
}

// RouteCanaryConfig sends a deterministic percentage of requests to a canary
// backend. The same key always maps to the same 0–99 bucket.
type RouteCanaryConfig struct {
	Backend string                `yaml:"backend"`
	Percent int                   `yaml:"percent"`
	Key     RouteTrafficKeyConfig `yaml:"key"`
}

// RouteTrafficKeyConfig selects the request attribute hashed for deterministic
// canary / mirror sampling. Header is tried first, then cookie; when both are
// empty or absent the client IP is used.
type RouteTrafficKeyConfig struct {
	Header string `yaml:"header"`
	Cookie string `yaml:"cookie"`
}

// RouteStickyConfig pins a client to one backend instance via cookie and/or
// header affinity.
type RouteStickyConfig struct {
	Cookie     string        `yaml:"cookie"`
	Header     string        `yaml:"header"`
	CookieTTL  time.Duration `yaml:"cookie_ttl"`
	CookiePath string        `yaml:"cookie_path"`
}

// RouteMirrorConfig fires an asynchronous shadow copy of the request to another
// backend. The client response always comes from the primary path; mirror
// failures are ignored. Bodies and sensitive headers are excluded by default.
type RouteMirrorConfig struct {
	Backend            string        `yaml:"backend"`
	Percent            int           `yaml:"percent"`
	MaxConcurrent      int           `yaml:"max_concurrent"`
	Timeout            time.Duration `yaml:"timeout"`
	ExcludeRequestBody bool          `yaml:"exclude_request_body"`
	ExcludeHeaders     []string      `yaml:"exclude_headers"`
	// excludeRequestBodySet tracks whether exclude_request_body was present so
	// runtime can default it to true when omitted.
	excludeRequestBodySet bool `yaml:"-"`
}

type MatchConfig struct {
	Path       string   `yaml:"path"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
	// Hosts restricts the route to requests whose Host header (port stripped,
	// case-insensitive) matches one of these values. Empty means any host.
	Hosts []string `yaml:"hosts"`
	// Headers requires each listed request header to equal the given value
	// (case-insensitive header name, case-sensitive value). Empty means no
	// header constraint. Useful for canary routing and API versioning.
	Headers map[string]string `yaml:"headers"`
	// Query requires each listed query parameter to equal the given value.
	// Empty means no query constraint.
	Query map[string]string `yaml:"query"`
}

type BackendConfig struct {
	Name string `yaml:"name"`
	// Protocol selects the wire protocol used to reach this backend:
	//   "http1" (default) — HTTP/1.1, with HTTP/2 negotiated via ALPN for https.
	//   "h2c"             — HTTP/2 over cleartext (prior knowledge), for gRPC and
	//                       streaming backends that do not terminate TLS.
	Protocol                string                          `yaml:"protocol"`
	Strategy                string                          `yaml:"strategy"`
	HealthCheck             HealthCheckConfig               `yaml:"health_check"`
	OutlierDetection        OutlierDetectionConfig          `yaml:"outlier_detection"`
	CircuitBreaker          CircuitBreakerConfig            `yaml:"circuit_breaker"`
	Retry                   RetryConfig                     `yaml:"retry"`
	TLS                     BackendTLSConfig                `yaml:"tls"`
	PropagateClientIdentity ClientIdentityPropagationConfig `yaml:"propagate_client_identity"`
	Bulkhead                BulkheadConfig                  `yaml:"bulkhead"`
	// Discovery enables dynamic DNS endpoint discovery. Mutually exclusive with
	// static Instances. Only DNS (A/AAAA/SRV) is supported — not K8s/Consul APIs.
	Discovery DiscoveryConfig  `yaml:"discovery"`
	Instances []InstanceConfig `yaml:"instances"`
}

// DiscoveryConfig selects a dynamic backend discovery mechanism.
type DiscoveryConfig struct {
	DNS *DNSDiscoveryConfig `yaml:"dns"`
}

// DNSDiscoveryConfig resolves backend instances from DNS A, AAAA, or SRV records.
// Kubernetes Service DNS names work through ordinary cluster DNS resolution.
type DNSDiscoveryConfig struct {
	// Name is the DNS name to query (A/AAAA) or the full SRV QNAME
	// (e.g. _http._tcp.orders.default.svc.cluster.local).
	Name string `yaml:"name"`
	// RecordType is A (default), AAAA, or SRV.
	RecordType string `yaml:"record_type"`
	// Port is required for A/AAAA when building instance URLs. Ignored for SRV
	// (the SRV port is used).
	Port int `yaml:"port"`
	// Scheme is http (default) or https for constructed instance URLs.
	Scheme string `yaml:"scheme"`
	// RefreshInterval caps how long Relay waits between re-resolves. The effective
	// interval is min(DNS TTL, refresh_interval) clamped by ttl_min/ttl_max.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	// TTLMin floors very short DNS TTLs (default 1s when unset at runtime).
	TTLMin time.Duration `yaml:"ttl_min"`
	// TTLMax caps long DNS TTLs. 0 means no extra cap beyond refresh_interval.
	TTLMax time.Duration `yaml:"ttl_max"`
	// Weight is the default instance weight for A/AAAA records (default 1).
	// SRV answers use the record weight.
	Weight int `yaml:"weight"`
}

// ClientIdentityPropagationConfig controls the small, Relay-owned set of mTLS
// client-certificate attributes that may cross the upstream trust boundary.
type ClientIdentityPropagationConfig struct {
	Enabled bool `yaml:"enabled"`
	// Fields is an explicit allowlist: subject, san_dns, san_email, san_ip,
	// san_uri, and fingerprint_sha256.
	Fields []string `yaml:"fields"`
	// AcknowledgeVerifiedHTTPS is required when the verified HTTPS upstream does
	// not also authenticate Relay with an outbound client certificate.
	AcknowledgeVerifiedHTTPS bool `yaml:"acknowledge_verified_https"`
}

// BulkheadConfig caps the number of simultaneous in-flight requests to a
// backend. Set MaxConcurrent > 0 to enable; 0 disables the bulkhead.
type BulkheadConfig struct {
	// MaxConcurrent is the maximum number of requests that may be in flight to
	// this backend at the same time. Requests that arrive when the limit is
	// reached are immediately rejected with 503 (fail fast, no queuing).
	MaxConcurrent int `yaml:"max_concurrent"`
}

// BackendTLSConfig controls outbound TLS toward a backend.
// All fields are optional. Set CertFile+KeyFile for mutual TLS (mTLS).
// Set CAFile to trust a private CA instead of the system root store.
type BackendTLSConfig struct {
	// CertFile is the path to the PEM-encoded client certificate for mTLS.
	CertFile string `yaml:"cert_file"`
	// KeyFile is the path to the PEM-encoded private key for mTLS.
	KeyFile string `yaml:"key_file"`
	// CAFile is the path to a PEM-encoded CA certificate bundle used to
	// verify the backend server certificate. Uses the system pool when empty.
	CAFile string `yaml:"ca_file"`
	// InsecureSkipVerify disables server certificate verification.
	// For development and testing only — never use in production.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// AcknowledgeInsecureSkipVerify must be set alongside insecure_skip_verify
	// to make the production-risking choice explicit in configuration review.
	AcknowledgeInsecureSkipVerify bool `yaml:"acknowledge_insecure_skip_verify"`
}

// RetryConfig enables request retries with exponential backoff for a backend.
// Set Attempts > 1 and at least one entry in On to enable retries.
type RetryConfig struct {
	// Attempts is the maximum total number of attempts (including the first).
	// 0 or 1 disables retry.
	Attempts int `yaml:"attempts"`
	// BackoffInit is the initial backoff duration. Defaults to 100ms.
	BackoffInit time.Duration `yaml:"backoff_init"`
	// BackoffMax caps the backoff duration. Defaults to 1s.
	BackoffMax time.Duration `yaml:"backoff_max"`
	// On lists the conditions that trigger a retry: "5xx" and/or "network_error".
	On []string `yaml:"on"`
	// AllowUnsafe, when true, permits retrying non-safe HTTP methods
	// (POST, PUT, PATCH, DELETE). Use only when the upstream is idempotent.
	AllowUnsafe bool `yaml:"allow_unsafe"`
	// BudgetRatio caps retries as a fraction of request volume to prevent retry
	// storms during an outage. Each completed request replenishes this many
	// tokens; each retry costs one. 0 (default) disables the budget (retries are
	// governed only by Attempts). Example: 0.2 caps sustained retries at ~20% of
	// traffic.
	BudgetRatio float64 `yaml:"budget_ratio"`
	// BudgetTokens is the token bucket capacity (initial burst allowance) when
	// BudgetRatio > 0. Defaults to 100 when zero.
	BudgetTokens int `yaml:"budget_tokens"`
}

// CircuitBreakerConfig enables a per-instance circuit breaker for a backend.
// Set Threshold > 0 to enable; zero disables it.
type CircuitBreakerConfig struct {
	// Threshold is the number of consecutive failures that trip the circuit.
	Threshold int `yaml:"threshold"`
	// Timeout is how long the circuit stays open before allowing a probe.
	// Defaults to 30s when zero.
	Timeout time.Duration `yaml:"timeout"`
}

type HealthCheckConfig struct {
	Interval       time.Duration        `yaml:"interval"`
	Timeout        time.Duration        `yaml:"timeout"`
	Path           string               `yaml:"path"`
	Method         string               `yaml:"method"`
	ExpectedStatus ExpectedStatusConfig `yaml:"expected_status"`
	Headers        map[string]string    `yaml:"headers"`
	Body           BodyMatcherConfig    `yaml:"body"`
	// MaxBodyBytes bounds response data read by a body matcher. It defaults to
	// 64 KiB when a matcher is configured and is capped by validation.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
}

// ExpectedStatusConfig accepts exactly one status policy. An empty policy
// preserves the legacy/default 2xx behavior.
type ExpectedStatusConfig struct {
	Exact int   `yaml:"exact"`
	Range []int `yaml:"range"`
	List  []int `yaml:"list"`
}

// UnmarshalYAML supports compact policies (204, "200-299", [200, 204]) and
// the explicit mapping form ({exact: 204}, {range: [200, 299]}, {list: [...]}).
func (c *ExpectedStatusConfig) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!int" {
			return node.Decode(&c.Exact)
		}
		value := strings.TrimSpace(node.Value)
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			exact, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("expected_status must be an HTTP status, range, or list")
			}
			c.Exact = exact
			return nil
		}
		minimum, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("expected_status range minimum: %w", err)
		}
		maximum, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("expected_status range maximum: %w", err)
		}
		c.Range = []int{minimum, maximum}
		return nil
	case yaml.SequenceNode:
		return node.Decode(&c.List)
	case yaml.MappingNode:
		type rawExpectedStatus ExpectedStatusConfig
		return node.Decode((*rawExpectedStatus)(c))
	default:
		return fmt.Errorf("expected_status must be an HTTP status, range, or list")
	}
}

type BodyMatcherConfig struct {
	Exact    string `yaml:"exact"`
	Contains string `yaml:"contains"`
	Regex    string `yaml:"regex"`
}

// OutlierDetectionConfig controls passive, per-instance ejection. It is enabled
// when either ConsecutiveFailures or FailureRatePercent is configured.
type OutlierDetectionConfig struct {
	Window               time.Duration `yaml:"window"`
	ConsecutiveFailures  int           `yaml:"consecutive_failures"`
	FailureRatePercent   float64       `yaml:"failure_rate_percent"`
	MinimumVolume        int           `yaml:"minimum_volume"`
	BaseEjectionDuration time.Duration `yaml:"base_ejection_duration"`
	MaxEjectionDuration  time.Duration `yaml:"max_ejection_duration"`
	MaxEjectionPercent   int           `yaml:"max_ejection_percent"`
	SuccessRecovery      bool          `yaml:"success_recovery"`
}

type InstanceConfig struct {
	ID  string `yaml:"id"`
	URL string `yaml:"url"`
	// Weight controls traffic share when strategy is "weighted_random".
	// Must be >= 0; 0 is treated as 1. Ignored by other strategies.
	Weight int `yaml:"weight"`
}

type MiddlewareConfig struct {
	Name    string                   `yaml:"name"`
	Type    string                   `yaml:"type"`
	Enabled bool                     `yaml:"enabled"`
	Config  MiddlewareSettingsConfig `yaml:"config"`
}

// RateLimitSelectorConfig is one ordered component of a rate-limit bucket key.
// Type is ip, route, header, claim, tenant, or identity. Header selectors use
// Name and verified JWT claim selectors use Claim.
type RateLimitSelectorConfig struct {
	Type  string `yaml:"type"`
	Name  string `yaml:"name"`
	Claim string `yaml:"claim"`
}

func (c *RateLimitSelectorConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		c.Type = node.Value
		return nil
	}
	type rawSelector RateLimitSelectorConfig
	return node.Decode((*rawSelector)(c))
}

type RateLimitKeyConfig struct {
	Selectors     []RateLimitSelectorConfig `yaml:"selectors"`
	Fallback      *RateLimitSelectorConfig  `yaml:"fallback"`
	RejectMissing bool                      `yaml:"reject_missing"`
	Namespace     string                    `yaml:"namespace"`
}

type MiddlewareSettingsConfig struct {
	SecretEnv string `yaml:"secret_env"`
	// SecretFile reads the JWT HS256 secret from a mounted file (e.g. a Kubernetes
	// Secret volume). Trimmed of trailing whitespace. Alternative to secret_env;
	// secret_env wins if both are set.
	SecretFile      string            `yaml:"secret_file"`
	ResolvedSecret  string            `yaml:"-"`
	Header          string            `yaml:"header"`
	ClaimsToHeaders map[string]string `yaml:"claims_to_headers"`
	// JWT algorithm selection: hs256 (default), rs256.
	Algorithm string `yaml:"algorithm"`
	// PublicKeyFile is the path to a PEM-encoded RSA public key for rs256.
	PublicKeyFile string `yaml:"public_key_file"`
	// JWKSUrl is a JWKS endpoint URL for rs256 key discovery.
	JWKSUrl string `yaml:"jwks_url"`
	// JWKSCacheTTL is how long JWKS keys are cached. Defaults to 5m when zero.
	JWKSCacheTTL time.Duration `yaml:"jwks_cache_ttl"`
	// JWKSStaleGrace is an opt-in availability window for keys removed by a
	// successful JWKS refresh or left stale by a failed refresh. Zero (default)
	// revokes removed keys immediately and fails closed when refresh is required.
	JWKSStaleGrace time.Duration `yaml:"jwks_stale_grace"`
	// ExpectedIssuer, when set, requires the JWT "iss" claim to match exactly.
	ExpectedIssuer string `yaml:"issuer"`
	// ExpectedAudience, when set, requires the JWT "aud" claim to contain it.
	ExpectedAudience string        `yaml:"audience"`
	MaxBytes         int64         `yaml:"max_bytes"`
	Allow            []string      `yaml:"allow"`
	Deny             []string      `yaml:"deny"`
	Strategy         string        `yaml:"strategy"`
	Limit            int           `yaml:"limit"`
	Window           time.Duration `yaml:"window"`
	By               string        `yaml:"by"`
	// Key defines an ordered, composable bucket identity. By remains supported
	// for legacy configurations and is mutually exclusive with key.selectors.
	RateLimitKey RateLimitKeyConfig `yaml:"key"`
	// RateLimitStore selects the backend for rate_limit and cache middleware:
	// "memory" (default, in-process) or "redis" (distributed).
	RateLimitStore string `yaml:"store"`
	// MemoryMaxBuckets caps the number of in-process rate limit keys.
	MemoryMaxBuckets int `yaml:"memory_max_buckets"`
	// MemoryBucketTTL expires idle in-process buckets. It must be at least Window.
	MemoryBucketTTL time.Duration `yaml:"memory_bucket_ttl"`
	// MemoryCleanupInterval controls the in-process stale bucket sweep.
	MemoryCleanupInterval time.Duration `yaml:"memory_cleanup_interval"`
	// RedisURL is the connection URL for the Redis rate limit store.
	// Accepts redis:// and rediss:// (TLS) schemes. Use redis_url_env for
	// production to avoid credentials in config files.
	RedisURL string `yaml:"redis_url"`
	// RedisURLEnv is the name of an environment variable containing the
	// Redis URL; overrides redis_url when set.
	RedisURLEnv string `yaml:"redis_url_env"`
	// RedisURLFile reads the Redis URL from a mounted file. Alternative to
	// redis_url/redis_url_env.
	RedisURLFile     string   `yaml:"redis_url_file"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	// JWTLogFailures emits structured Warn logs on JWT rejection (missing header, parse/signature/claims).
	// Does not log the raw token or secret; payload inspection lists claim keys and exp only.
	JWTLogFailures bool `yaml:"jwt_log_failures"`
	// Header middleware fields
	RequestSet  map[string]string `yaml:"request_set"`
	RequestDel  []string          `yaml:"request_del"`
	ResponseSet map[string]string `yaml:"response_set"`
	ResponseDel []string          `yaml:"response_del"`
	// API key middleware fields
	KeyHeader string `yaml:"key_header"`
	KeyQuery  string `yaml:"key_query"`
	// AcknowledgeAPIKeyInQuery must be set when KeyQuery is configured because
	// query-string credentials can leak through logs, caches, and referrers.
	// It is a validation-only acknowledgement and does not alter request handling.
	AcknowledgeAPIKeyInQuery bool   `yaml:"acknowledge_api_key_in_query"`
	KeysEnv                  string `yaml:"keys_env"`
	ResolvedKeys             string `yaml:"-"` // populated from KeysEnv by ResolveEnv
	KeysFile                 string `yaml:"keys_file"`
	KeyToHeader              string `yaml:"key_to_header"`
	// Cache middleware fields
	TTL             time.Duration `yaml:"ttl"`
	CacheMethods    []string      `yaml:"methods"`
	CacheableStatus []int         `yaml:"cacheable_status"`
	MaxObjectBytes  int64         `yaml:"max_object_bytes"`
	MaxEntries      int           `yaml:"max_entries"`
	Vary            []string      `yaml:"vary"`
	// CacheNamespace prefixes Redis keys for the cache middleware.
	CacheNamespace string `yaml:"namespace"`
	// CacheOperationTimeout bounds a single Redis cache command.
	CacheOperationTimeout time.Duration `yaml:"operation_timeout"`
	// OIDC discovery for jwt middleware: derive jwks_uri from the issuer's
	// well-known document instead of configuring jwks_url directly.
	OIDCIssuer string `yaml:"oidc_issuer"`
	// OAuth2 token introspection middleware (RFC 7662) fields.
	IntrospectionURL string `yaml:"introspection_url"`
	ClientID         string `yaml:"client_id"`
	ClientSecretEnv  string `yaml:"client_secret_env"`
	// ClientSecretFile reads the introspection client secret from a mounted file.
	// Alternative to client_secret_env.
	ClientSecretFile      string        `yaml:"client_secret_file"`
	ResolvedClientSecret  string        `yaml:"-"` // populated from ClientSecretEnv/ClientSecretFile
	RequiredScopes        []string      `yaml:"required_scopes"`
	IntrospectionCacheTTL time.Duration `yaml:"cache_ttl"`
	// External authorization middleware (ext_authz) fields.
	AuthzURL    string `yaml:"authz_url"`
	AuthzMethod string `yaml:"authz_method"`
	AuthzBody   string `yaml:"authz_body"`
	// AuthzMaxBodyBytes bounds original and metadata authorization bodies.
	AuthzMaxBodyBytes   int64         `yaml:"authz_max_body_bytes"`
	AuthzContentType    string        `yaml:"authz_content_type"`
	AuthzForwardHeaders []string      `yaml:"forward_headers"`
	AuthzCopyHeaders    []string      `yaml:"copy_headers"`
	AuthzTimeout        time.Duration `yaml:"authz_timeout"`
	// AuthzAllowInsecureHTTP explicitly permits an HTTP ext_authz endpoint.
	// Keep false in production because forwarded credentials otherwise travel
	// without transport encryption.
	AuthzAllowInsecureHTTP bool `yaml:"allow_insecure_http"`
	FailOpen               bool `yaml:"fail_open"`
	// AcknowledgeExtAuthzFailOpen must be set when ext_authz fail_open is true.
	// It is a validation-only acknowledgement and does not alter request handling.
	AcknowledgeExtAuthzFailOpen bool `yaml:"acknowledge_ext_authz_fail_open"`
	// Security headers middleware fields. A value of "off" explicitly disables
	// a header inherited from a preset.
	SecurityHeadersPreset   string `yaml:"preset"`
	StrictTransportSecurity string `yaml:"strict_transport_security"`
	ContentSecurityPolicy   string `yaml:"content_security_policy"`
	XFrameOptions           string `yaml:"x_frame_options"`
	XContentTypeOptions     string `yaml:"x_content_type_options"`
	ReferrerPolicy          string `yaml:"referrer_policy"`
	PermissionsPolicy       string `yaml:"permissions_policy"`
}

type ObservabilityConfig struct {
	Logs       LogsConfig       `yaml:"logs"`
	Fabric     FabricConfig     `yaml:"fabric"`
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Tracing    TracingConfig    `yaml:"tracing"`
}

// TracingConfig controls OpenTelemetry distributed tracing.
type TracingConfig struct {
	// Enabled activates tracing. When false, a no-op tracer is used.
	Enabled bool `yaml:"enabled"`
	// Exporter selects the trace exporter: "otlp_grpc", "otlp_http", or "stdout".
	Exporter string `yaml:"exporter"`
	// Endpoint is the collector address (e.g. "localhost:4317" for OTLP gRPC).
	// Defaults to the OpenTelemetry SDK default when empty.
	Endpoint string `yaml:"endpoint"`
	// SampleRate is the fraction of traces to sample (0.0–1.0). Default 1.0.
	SampleRate    float64 `yaml:"sample_rate"`
	SampleRateSet bool    `yaml:"-"`
	// ServiceName overrides the service name reported to the collector.
	// Falls back to observability.fabric.service_name, then "relay".
	ServiceName string `yaml:"service_name"`
}

type PrometheusConfig struct {
	// Path is the scrape endpoint. Defaults to /_relay/metrics/prometheus when empty.
	Path string `yaml:"path"`
	// AllowedCIDRs lists IP ranges (in addition to loopback) allowed to reach the
	// metrics and Prometheus endpoints, matched against the real TCP peer. Empty
	// (default) keeps the endpoints loopback-only. Set the pod/cluster CIDR to let
	// a Prometheus scraper (e.g. a ServiceMonitor) reach them.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
}

// FabricConfig controls Algoryn Fabric protobuf telemetry (MetricSnapshot + Event) toward Beacon and peers.
type FabricConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ServiceName string `yaml:"service_name"`
	QueueSize   int    `yaml:"queue_size"`
}

type LogsConfig struct {
	Level      string          `yaml:"level"`
	Format     string          `yaml:"format"`
	File       string          `yaml:"file"`
	MaxSizeMB  int             `yaml:"max_size_mb"`
	MaxAgeDays int             `yaml:"max_age_days"`
	Compress   bool            `yaml:"compress"`
	Access     AccessLogConfig `yaml:"access"`
	OTLP       OTLPLogsConfig  `yaml:"otlp"`
}

// AccessLogConfig controls the bounded set of request attributes emitted by
// the access logger. Fields is an allowlist, never a free-form expression.
type AccessLogConfig struct {
	Fields        []string             `yaml:"fields"`
	FieldPolicies map[string]string    `yaml:"field_policies"`
	Headers       []AccessLogSelection `yaml:"headers"`
	Query         []AccessLogSelection `yaml:"query"`
	Hash          AccessLogHashConfig  `yaml:"hash"`
}

type AccessLogSelection struct {
	Name   string `yaml:"name"`
	Policy string `yaml:"policy"`
}

type AccessLogHashConfig struct {
	Algorithm      string `yaml:"algorithm"`
	SecretEnv      string `yaml:"secret_env"`
	SecretFile     string `yaml:"secret_file"`
	ResolvedSecret string `yaml:"-"`
}

// OTLPLogsConfig adds an asynchronous OTLP sink while preserving stdout/file.
type OTLPLogsConfig struct {
	Enabled         bool              `yaml:"enabled"`
	Exporter        string            `yaml:"exporter"`
	Endpoint        string            `yaml:"endpoint"`
	Insecure        bool              `yaml:"insecure"`
	Headers         map[string]string `yaml:"headers"`
	HeadersEnv      string            `yaml:"headers_env"`
	HeadersFile     string            `yaml:"headers_file"`
	ResolvedHeaders string            `yaml:"-"`
	QueueSize       int               `yaml:"queue_size"`
	BatchSize       int               `yaml:"batch_size"`
	BatchTimeout    time.Duration     `yaml:"batch_timeout"`
	ExportTimeout   time.Duration     `yaml:"export_timeout"`
	ServiceName     string            `yaml:"service_name"`
}

type ReloadConfig struct {
	Watch    bool          `yaml:"watch"`
	Enabled  bool          `yaml:"enabled"`
	Debounce time.Duration `yaml:"debounce"`
}

func (c *Config) Validate() error {
	if c == nil {
		return errNilConfig
	}
	return validateConfig(c)
}

func Validate(c *Config) error {
	if c == nil {
		return errNilConfig
	}
	return c.Validate()
}
