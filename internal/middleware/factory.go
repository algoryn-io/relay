package middleware

import (
	"fmt"
	"log/slog"

	"algoryn.io/relay/internal/config"
)

func Build(def config.MiddlewareRuntime, logger *slog.Logger) (Middleware, error) {
	switch def.Type {
	case "jwt":
		return NewJWT(JWTConfig{
			Algorithm:       def.Config.Algorithm,
			Secret:          def.Config.ResolvedSecret,
			PublicKeyFile:   def.Config.PublicKeyFile,
			JWKSUrl:         def.Config.JWKSUrl,
			JWKSCacheTTL:    def.Config.JWKSCacheTTL,
			Header:          def.Config.Header,
			ClaimsToHeaders: def.Config.ClaimsToHeaders,
			Logger:          logger,
			LogFailures:     def.Config.JWTLogFailures,
		})
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
		return NewBodyLimit(BodyLimitConfig{
			MaxBytes: def.Config.MaxBytes,
		})
	case "ip_filter":
		return NewIPFilter(IPFilterConfig{
			Allow: def.Config.Allow,
			Deny:  def.Config.Deny,
		})
	case "cors":
		return NewCORS(CORSConfig{
			AllowedOrigins:   def.Config.AllowedOrigins,
			AllowedMethods:   def.Config.AllowedMethods,
			AllowedHeaders:   def.Config.AllowedHeaders,
			AllowCredentials: def.Config.AllowCredentials,
		})
	case "header":
		return NewHeader(HeaderConfig{
			RequestSet:  def.Config.RequestSet,
			RequestDel:  def.Config.RequestDel,
			ResponseSet: def.Config.ResponseSet,
			ResponseDel: def.Config.ResponseDel,
		})
	case "api_key":
		keys, err := LoadAPIKeys(def.Config.ResolvedKeys, def.Config.KeysFile)
		if err != nil {
			return nil, fmt.Errorf("api_key middleware %q: %w", def.Name, err)
		}
		return NewAPIKey(APIKeyConfig{
			KeyHeader:   def.Config.KeyHeader,
			KeyQuery:    def.Config.KeyQuery,
			Keys:        keys,
			KeyToHeader: def.Config.KeyToHeader,
		})
	default:
		return nil, fmt.Errorf("unsupported middleware type %q", def.Type)
	}
}

func BuildRegistry(defs map[string]config.MiddlewareRuntime, logger *slog.Logger) (map[string]Middleware, error) {
	registry := make(map[string]Middleware, len(defs))
	for name, def := range defs {
		mw, err := Build(def, logger)
		if err != nil {
			return nil, fmt.Errorf("build middleware %q: %w", name, err)
		}
		registry[name] = mw
	}
	return registry, nil
}
