package middleware

import (
	"fmt"

	"algoryn.io/relay/internal/config"
)

func Build(def config.MiddlewareRuntime) (Middleware, error) {
	switch def.Type {
	case "jwt":
		return NewJWT(JWTConfig{
			Secret: def.Config.ResolvedSecret,
			Header: def.Config.Header,
		})
	case "rate_limit":
		return NewRateLimit(RateLimitConfig{
			Strategy: Strategy(def.Config.Strategy),
			Limit:    def.Config.Limit,
			Window:   def.Config.Window,
			By:       def.Config.By,
			Header:   def.Config.Header,
		})
	case "body_limit":
		return NewBodyLimit(BodyLimitConfig{
			MaxBytes: def.Config.MaxBytes,
		})
	case "cors":
		return NewCORS(CORSConfig{
			AllowedOrigins:   def.Config.AllowedOrigins,
			AllowedMethods:   def.Config.AllowedMethods,
			AllowedHeaders:   def.Config.AllowedHeaders,
			AllowCredentials: def.Config.AllowCredentials,
		})
	default:
		return nil, fmt.Errorf("unsupported middleware type %q", def.Type)
	}
}

func BuildRegistry(defs map[string]config.MiddlewareRuntime) (map[string]Middleware, error) {
	registry := make(map[string]Middleware, len(defs))
	for name, def := range defs {
		mw, err := Build(def)
		if err != nil {
			return nil, fmt.Errorf("build middleware %q: %w", name, err)
		}
		registry[name] = mw
	}
	return registry, nil
}
