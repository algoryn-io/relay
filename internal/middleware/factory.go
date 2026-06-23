package middleware

import (
	"fmt"
	"io"
	"log/slog"

	"algoryn.io/relay/internal/config"
)

// Build constructs a middleware. The returned io.Closer (nil for stateless
// middleware) owns any resources that must be released when the middleware is
// discarded, e.g. on config reload.
func Build(def config.MiddlewareRuntime, logger *slog.Logger) (Middleware, io.Closer, error) {
	switch def.Type {
	case "jwt":
		mw, err := NewJWT(JWTConfig{
			Algorithm:        def.Config.Algorithm,
			Secret:           def.Config.ResolvedSecret,
			PublicKeyFile:    def.Config.PublicKeyFile,
			JWKSUrl:          def.Config.JWKSUrl,
			JWKSCacheTTL:     def.Config.JWKSCacheTTL,
			Header:           def.Config.Header,
			ClaimsToHeaders:  def.Config.ClaimsToHeaders,
			ExpectedIssuer:   def.Config.ExpectedIssuer,
			ExpectedAudience: def.Config.ExpectedAudience,
			Logger:           logger,
			LogFailures:      def.Config.JWTLogFailures,
		})
		return mw, nil, err
	case "rate_limit":
		redisURL := def.Config.RedisURL
		// ResolveEnv writes the resolved env var into RedisURL when RedisURLEnv
		// is set, so by this point RedisURL already holds the final value.
		return NewRateLimit(RateLimitConfig{
			Strategy: Strategy(def.Config.Strategy),
			Limit:    def.Config.Limit,
			Window:   def.Config.Window,
			By:       def.Config.By,
			Header:   def.Config.Header,
			Store:    def.Config.RateLimitStore,
			RedisURL: redisURL,
		})
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
	default:
		return nil, nil, fmt.Errorf("unsupported middleware type %q", def.Type)
	}
}

// BuildRegistry builds all middlewares. The returned closers own resources that
// must be released when this registry is replaced (config reload) or the server
// shuts down; close them via CloseAll.
func BuildRegistry(defs map[string]config.MiddlewareRuntime, logger *slog.Logger) (map[string]Middleware, []io.Closer, error) {
	registry := make(map[string]Middleware, len(defs))
	var closers []io.Closer
	for name, def := range defs {
		mw, closer, err := Build(def, logger)
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
