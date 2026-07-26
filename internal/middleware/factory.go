package middleware

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"algoryn.io/relay/internal/config"
)

// Build constructs a middleware. The returned io.Closer (nil for stateless
// middleware) owns any resources that must be released when the middleware is
// discarded, e.g. on config reload.
func Build(def config.MiddlewareRuntime, logger *slog.Logger, rateLimitObservers ...any) (Middleware, io.Closer, error) {
	switch def.Type {
	case "jwt":
		var client *http.Client
		var closer io.Closer
		if def.Config.JWKSUrl != "" || def.Config.OIDCIssuer != "" {
			client, closer = newOwnedHTTPClient(10 * time.Second)
		}
		mw, err := NewJWT(JWTConfig{
			Algorithm:        def.Config.Algorithm,
			Secret:           def.Config.ResolvedSecret,
			PublicKeyFile:    def.Config.PublicKeyFile,
			JWKSUrl:          def.Config.JWKSUrl,
			JWKSCacheTTL:     def.Config.JWKSCacheTTL,
			JWKSStaleGrace:   def.Config.JWKSStaleGrace,
			OIDCIssuer:       def.Config.OIDCIssuer,
			Header:           def.Config.Header,
			ClaimsToHeaders:  def.Config.ClaimsToHeaders,
			ExpectedIssuer:   def.Config.ExpectedIssuer,
			ExpectedAudience: def.Config.ExpectedAudience,
			Logger:           logger,
			LogFailures:      def.Config.JWTLogFailures,
			JWKSClient:       client,
		})
		if err != nil {
			CloseAll([]io.Closer{closer})
			return nil, nil, err
		}
		return mw, closer, nil
	case "rate_limit":
		redisURL := def.Config.RedisURL
		var metrics RateLimitMetrics
		var events RateLimitOperationalEvents
		for _, observer := range rateLimitObservers {
			if candidate, ok := observer.(RateLimitMetrics); ok {
				metrics = candidate
			}
			if candidate, ok := observer.(RateLimitOperationalEvents); ok {
				events = candidate
			}
		}
		// ResolveEnv writes the resolved env var into RedisURL when RedisURLEnv
		// is set, so by this point RedisURL already holds the final value.
		key := RateLimitKeyConfig{
			RejectMissing: def.Config.RateLimitKey.RejectMissing,
			Namespace:     def.Config.RateLimitKey.Namespace,
		}
		for _, selector := range def.Config.RateLimitKey.Selectors {
			key.Selectors = append(key.Selectors, RateLimitSelector{
				Type: selector.Type, Name: selector.Name, Claim: selector.Claim,
			})
		}
		if fallback := def.Config.RateLimitKey.Fallback; fallback != nil {
			key.Fallback = &RateLimitSelector{
				Type: fallback.Type, Name: fallback.Name, Claim: fallback.Claim,
			}
		}
		mw, closer, err := NewRateLimit(RateLimitConfig{
			Strategy:              Strategy(def.Config.Strategy),
			Limit:                 def.Config.Limit,
			Window:                def.Config.Window,
			By:                    def.Config.By,
			Header:                def.Config.Header,
			Key:                   key,
			Store:                 def.Config.RateLimitStore,
			RedisURL:              redisURL,
			FailOpen:              def.Config.FailOpen,
			MemoryMaxBuckets:      def.Config.MemoryMaxBuckets,
			MemoryBucketTTL:       def.Config.MemoryBucketTTL,
			MemoryCleanupInterval: def.Config.MemoryCleanupInterval,
			Metrics:               metrics,
			Events:                events,
			ObserverKey:           def.Name,
		})
		return mw, makeOnceCloser(closer), err
	case "body_limit":
		mw, err := NewBodyLimit(BodyLimitConfig{
			MaxBytes: def.Config.MaxBytes,
		})
		return mw, nil, err
	case "ip_filter":
		mw, err := NewIPFilter(IPFilterConfig{
			Allow: def.Config.Allow,
			Deny:  def.Config.Deny,
		})
		return mw, nil, err
	case "cors":
		mw, err := NewCORS(CORSConfig{
			AllowedOrigins:   def.Config.AllowedOrigins,
			AllowedMethods:   def.Config.AllowedMethods,
			AllowedHeaders:   def.Config.AllowedHeaders,
			AllowCredentials: def.Config.AllowCredentials,
		})
		return mw, nil, err
	case "header":
		mw, err := NewHeader(HeaderConfig{
			RequestSet:  def.Config.RequestSet,
			RequestDel:  def.Config.RequestDel,
			ResponseSet: def.Config.ResponseSet,
			ResponseDel: def.Config.ResponseDel,
		})
		return mw, nil, err
	case "security_headers":
		mw, err := NewSecurityHeaders(SecurityHeadersConfig{
			Preset:                  def.Config.SecurityHeadersPreset,
			StrictTransportSecurity: def.Config.StrictTransportSecurity,
			ContentSecurityPolicy:   def.Config.ContentSecurityPolicy,
			XFrameOptions:           def.Config.XFrameOptions,
			XContentTypeOptions:     def.Config.XContentTypeOptions,
			ReferrerPolicy:          def.Config.ReferrerPolicy,
			PermissionsPolicy:       def.Config.PermissionsPolicy,
		})
		return mw, nil, err
	case "compression":
		mw, err := NewCompression(CompressionConfig{
			Encodings:           def.Config.CompressionEncodings,
			MinBytes:            def.Config.CompressionMinBytes,
			GzipLevel:           def.Config.CompressionGzipLevel,
			BrotliQuality:       def.Config.CompressionBrotliQuality,
			ContentTypes:        def.Config.CompressionContentTypes,
			ExcludeContentTypes: def.Config.CompressionExcludeContentTypes,
			ExcludeStatus:       def.Config.CompressionExcludeStatus,
		})
		return mw, nil, err
	case "json_body_transform":
		mw, err := NewJSONBodyTransform(JSONBodyTransformConfig{
			MaxBytes:     def.Config.MaxBytes,
			ContentTypes: def.Config.CompressionContentTypes,
			Request: JSONBodyOps{
				Rename: def.Config.JSONBodyRequest.Rename,
				Add:    def.Config.JSONBodyRequest.Add,
				Remove: def.Config.JSONBodyRequest.Remove,
			},
			Response: JSONBodyOps{
				Rename: def.Config.JSONBodyResponse.Rename,
				Add:    def.Config.JSONBodyResponse.Add,
				Remove: def.Config.JSONBodyResponse.Remove,
			},
		})
		return mw, nil, err
	case "api_key":
		keys, err := LoadAPIKeys(def.Config.ResolvedKeys, def.Config.KeysFile)
		if err != nil {
			return nil, nil, fmt.Errorf("api_key middleware %q: %w", def.Name, err)
		}
		mw, err := NewAPIKey(APIKeyConfig{
			KeyHeader:   def.Config.KeyHeader,
			KeyQuery:    def.Config.KeyQuery,
			Keys:        keys,
			KeyToHeader: def.Config.KeyToHeader,
		})
		return mw, nil, err
	case "cache":
		mw, closer, err := NewCache(CacheConfig{
			TTL:              def.Config.TTL,
			Methods:          def.Config.CacheMethods,
			CacheableStatus:  def.Config.CacheableStatus,
			MaxObjectBytes:   def.Config.MaxObjectBytes,
			MaxEntries:       def.Config.MaxEntries,
			Vary:             def.Config.Vary,
			Store:            def.Config.RateLimitStore,
			RedisURL:         def.Config.RedisURL,
			Namespace:        def.Config.CacheNamespace,
			OperationTimeout: def.Config.CacheOperationTimeout,
			FailOpen:         def.Config.FailOpen,
		})
		if err != nil {
			return nil, nil, err
		}
		return mw, makeOnceCloser(closer), nil
	case "oauth2":
		client, closer := newOwnedHTTPClient(defaultIntrospectionTimeout)
		mw, err := NewIntrospection(IntrospectionConfig{
			URL:            def.Config.IntrospectionURL,
			ClientID:       def.Config.ClientID,
			ClientSecret:   def.Config.ResolvedClientSecret,
			RequiredScopes: def.Config.RequiredScopes,
			Header:         def.Config.Header,
			CacheTTL:       def.Config.IntrospectionCacheTTL,
			Logger:         logger,
			Client:         client,
		})
		if err != nil {
			_ = closer.Close()
			return nil, nil, err
		}
		return mw, closer, nil
	case "ext_authz":
		timeout := def.Config.AuthzTimeout
		if timeout <= 0 {
			timeout = defaultExtAuthzTimeout
		}
		client, closer := newOwnedHTTPClient(timeout)
		mw, err := NewExtAuthz(ExtAuthzConfig{
			URL:               def.Config.AuthzURL,
			Method:            def.Config.AuthzMethod,
			Body:              ExtAuthzBodyMode(def.Config.AuthzBody),
			MaxBodyBytes:      def.Config.AuthzMaxBodyBytes,
			ContentType:       def.Config.AuthzContentType,
			ForwardHeaders:    def.Config.AuthzForwardHeaders,
			CopyHeaders:       def.Config.AuthzCopyHeaders,
			Timeout:           def.Config.AuthzTimeout,
			FailOpen:          def.Config.FailOpen,
			AllowInsecureHTTP: def.Config.AuthzAllowInsecureHTTP,
			Logger:            logger,
			Client:            client,
		})
		if err != nil {
			_ = closer.Close()
			return nil, nil, err
		}
		return mw, closer, nil
	default:
		return nil, nil, fmt.Errorf("unsupported middleware type %q", def.Type)
	}
}

type onceCloser struct {
	once sync.Once
	fn   func() error
}

func (c *onceCloser) Close() error {
	var err error
	c.once.Do(func() { err = c.fn() })
	return err
}

func makeOnceCloser(c io.Closer) io.Closer {
	if c == nil {
		return nil
	}
	return &onceCloser{fn: c.Close}
}

func newOwnedHTTPClient(timeout time.Duration) (*http.Client, io.Closer) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: transport, Timeout: timeout}
	return client, &onceCloser{fn: func() error {
		transport.CloseIdleConnections()
		return nil
	}}
}

// BuildRegistry builds all middlewares. The returned closers own resources that
// must be released when this registry is replaced (config reload) or the server
// shuts down; close them via CloseAll.
func BuildRegistry(defs map[string]config.MiddlewareRuntime, logger *slog.Logger, rateLimitObservers ...any) (map[string]Middleware, []io.Closer, error) {
	registry := make(map[string]Middleware, len(defs))
	var closers []io.Closer
	for name, def := range defs {
		mw, closer, err := Build(def, logger, rateLimitObservers...)
		if err != nil {
			CloseAll(closers) // don't leak resources already built this pass
			return nil, nil, fmt.Errorf("build middleware %q: %w", name, err)
		}
		registry[name] = mw
		if closer != nil {
			closers = append(closers, closer)
		}
	}
	return registry, closers, nil
}

// CloseAll closes every closer, ignoring nil entries.
func CloseAll(closers []io.Closer) {
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
}
