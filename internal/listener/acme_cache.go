package listener

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"algoryn.io/relay/internal/config"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/acme/autocert"
)

const (
	defaultACMERedisOperationTimeout = 500 * time.Millisecond
	defaultACMELockWaitTimeout       = 3 * time.Minute
	defaultACMELockTTL               = 2 * time.Minute
	defaultACMELockPollInterval      = 100 * time.Millisecond
)

var (
	acmePutAndUnlockScript = redis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('DEL', KEYS[2])
return 1
`)
	acmeDeleteAndUnlockScript = redis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then
  return 0
end
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
return 1
`)
	acmeUnlockScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)
	acmeRenewScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
`)
)

type acmeLease struct {
	token  string
	cancel context.CancelFunc
	done   chan struct{}
	lost   atomic.Bool
}

// redisACMECache implements autocert.Cache and serializes cache misses with a
// renewable Redis lease. The replica that owns a miss may publish only while
// its owner token still matches, preventing stale issuers from overwriting data.
type redisACMECache struct {
	client         redis.Cmdable
	closer         io.Closer
	prefix         string
	operation      time.Duration
	wait           time.Duration
	lockTTL        time.Duration
	renewInterval  time.Duration
	pollInterval   time.Duration
	mu             sync.Mutex
	leases         map[string]*acmeLease
	closed         bool
	closeOnce      sync.Once
	renewWaitGroup sync.WaitGroup
}

func newRedisACMECache(cfg config.TLSConfig) (*redisACMECache, error) {
	opts, err := redis.ParseURL(strings.TrimSpace(cfg.ACMECache.RedisURL))
	if err != nil {
		return nil, fmt.Errorf("parse ACME Redis URL: %w", err)
	}
	client := redis.NewClient(opts)
	cache, err := newRedisACMECacheFromClient(client, client, cfg)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return cache, nil
}

func newRedisACMECacheFromClient(client redis.Cmdable, closer io.Closer, cfg config.TLSConfig) (*redisACMECache, error) {
	if client == nil {
		return nil, fmt.Errorf("ACME Redis client must not be nil")
	}
	cacheCfg := cfg.ACMECache
	operation := cacheCfg.OperationTimeout
	if operation == 0 {
		operation = defaultACMERedisOperationTimeout
	}
	wait := cacheCfg.LockWaitTimeout
	if wait == 0 {
		wait = defaultACMELockWaitTimeout
	}
	lockTTL := cacheCfg.LockTTL
	if lockTTL == 0 {
		lockTTL = defaultACMELockTTL
	}
	renew := cacheCfg.LockRenewInterval
	if renew == 0 {
		renew = lockTTL / 3
	}
	cache := &redisACMECache{
		client:        client,
		closer:        closer,
		prefix:        acmeRedisNamespace(cacheCfg.Namespace, cfg.ACMEEmail, cfg.Domains),
		operation:     operation,
		wait:          wait,
		lockTTL:       lockTTL,
		renewInterval: renew,
		pollInterval:  defaultACMELockPollInterval,
		leases:        make(map[string]*acmeLease),
	}
	ctx, cancel := context.WithTimeout(context.Background(), operation)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping ACME Redis cache: %w", err)
	}
	return cache, nil
}

func acmeRedisNamespace(namespace, account string, domains []string) string {
	sortedDomains := append([]string(nil), domains...)
	for i := range sortedDomains {
		sortedDomains[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sortedDomains[i]), "."))
	}
	sort.Strings(sortedDomains)
	scope := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(account)) + "\x00" + strings.Join(sortedDomains, "\x00")))
	operator := strings.Trim(strings.TrimSpace(namespace), ":")
	if operator == "" {
		operator = "default"
	}
	return "relay:acme:" + operator + ":" + hex.EncodeToString(scope[:])
}

func (c *redisACMECache) keys(key string) (string, string) {
	sum := sha256.Sum256([]byte(key))
	suffix := hex.EncodeToString(sum[:])
	return c.prefix + ":data:" + suffix, c.prefix + ":lease:" + suffix
}

func (c *redisACMECache) Get(ctx context.Context, key string) ([]byte, error) {
	dataKey, lockKey := c.keys(key)
	deadline := time.Now().Add(c.wait)
	for {
		value, err := c.get(ctx, dataKey)
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("read ACME Redis cache: %w", err)
		}
		if c.isClosed() {
			return nil, fmt.Errorf("ACME Redis cache is closed")
		}

		if existing := c.currentLease(key); existing != nil {
			if err := c.waitForLease(ctx, existing, deadline); err != nil {
				return nil, err
			}
			continue
		}

		token, err := secureLeaseToken()
		if err != nil {
			return nil, err
		}
		acquired, err := c.tryAcquire(ctx, lockKey, token)
		if err != nil {
			return nil, fmt.Errorf("acquire ACME issuance lease: %w", err)
		}
		if acquired {
			// Close the race between the initial miss and lease acquisition.
			value, readErr := c.get(ctx, dataKey)
			if readErr == nil {
				_ = c.unlock(context.Background(), lockKey, token)
				return value, nil
			}
			if !errors.Is(readErr, redis.Nil) {
				_ = c.unlock(context.Background(), lockKey, token)
				return nil, fmt.Errorf("recheck ACME Redis cache: %w", readErr)
			}
			lease := c.startLease(key, lockKey, token)
			if lease.lost.Load() {
				return nil, fmt.Errorf("ACME Redis cache closed during lease acquisition")
			}
			return nil, autocert.ErrCacheMiss
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for ACME issuance lease")
		}
		if err := sleepContext(ctx, c.pollInterval); err != nil {
			return nil, err
		}
	}
}

func (c *redisACMECache) Put(ctx context.Context, key string, data []byte) error {
	lease, err := c.ensureLease(ctx, key)
	if err != nil {
		return err
	}
	if lease.lost.Load() {
		return fmt.Errorf("ACME issuance lease was lost before cache write")
	}
	dataKey, lockKey := c.keys(key)
	cmdCtx, cancel := c.commandContext(ctx)
	defer cancel()
	result, err := acmePutAndUnlockScript.Run(cmdCtx, c.client, []string{dataKey, lockKey}, lease.token, data).Int64()
	c.finishLease(key, lease)
	if err != nil {
		return fmt.Errorf("write ACME Redis cache: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("ACME issuance lease was lost before cache write")
	}
	return nil
}

func (c *redisACMECache) Delete(ctx context.Context, key string) error {
	lease, err := c.ensureLease(ctx, key)
	if err != nil {
		return err
	}
	dataKey, lockKey := c.keys(key)
	cmdCtx, cancel := c.commandContext(ctx)
	defer cancel()
	result, err := acmeDeleteAndUnlockScript.Run(cmdCtx, c.client, []string{dataKey, lockKey}, lease.token).Int64()
	c.finishLease(key, lease)
	if err != nil {
		return fmt.Errorf("delete ACME Redis cache: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("ACME issuance lease was lost before cache delete")
	}
	return nil
}

func (c *redisACMECache) ensureLease(ctx context.Context, key string) (*acmeLease, error) {
	if lease := c.currentLease(key); lease != nil {
		return lease, nil
	}
	_, lockKey := c.keys(key)
	token, err := secureLeaseToken()
	if err != nil {
		return nil, err
	}
	acquired, err := c.tryAcquire(ctx, lockKey, token)
	if err != nil {
		return nil, fmt.Errorf("acquire ACME cache mutation lease: %w", err)
	}
	if !acquired {
		return nil, fmt.Errorf("ACME cache mutation lease is held by another replica")
	}
	return c.startLease(key, lockKey, token), nil
}

func (c *redisACMECache) startLease(key, lockKey, token string) *acmeLease {
	// Bound ownership as well as waiter latency. If autocert fails before Put or
	// Delete, there is no completion callback; this timeout stops renewal so the
	// Redis TTL can release the abandoned lease.
	ctx, cancel := context.WithTimeout(context.Background(), c.wait)
	lease := &acmeLease{token: token, cancel: cancel, done: make(chan struct{})}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancel()
		close(lease.done)
		lease.lost.Store(true)
		_ = c.unlock(context.Background(), lockKey, token)
		return lease
	}
	c.leases[key] = lease
	c.renewWaitGroup.Add(1)
	c.mu.Unlock()
	go c.renewLease(ctx, key, lockKey, lease)
	return lease
}

func (c *redisACMECache) renewLease(ctx context.Context, key, lockKey string, lease *acmeLease) {
	defer c.renewWaitGroup.Done()
	defer close(lease.done)
	ticker := time.NewTicker(c.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			lease.lost.Store(true)
			c.removeLease(key, lease)
			_ = c.unlock(context.Background(), lockKey, lease.token)
			return
		case <-ticker.C:
			cmdCtx, cancel := context.WithTimeout(context.Background(), c.operation)
			result, err := acmeRenewScript.Run(cmdCtx, c.client, []string{lockKey}, lease.token, c.lockTTL.Milliseconds()).Int64()
			cancel()
			if err != nil || result != 1 {
				lease.lost.Store(true)
				c.removeLease(key, lease)
				return
			}
		}
	}
}

func (c *redisACMECache) finishLease(key string, lease *acmeLease) {
	c.removeLease(key, lease)
	lease.cancel()
	<-lease.done
}

func (c *redisACMECache) removeLease(key string, lease *acmeLease) {
	c.mu.Lock()
	if c.leases[key] == lease {
		delete(c.leases, key)
	}
	c.mu.Unlock()
}

func (c *redisACMECache) currentLease(key string) *acmeLease {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leases[key]
}

func (c *redisACMECache) waitForLease(ctx context.Context, lease *acmeLease, deadline time.Time) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return fmt.Errorf("timed out waiting for local ACME issuance lease")
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-lease.done:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for local ACME issuance lease")
	}
}

func (c *redisACMECache) tryAcquire(ctx context.Context, lockKey, token string) (bool, error) {
	cmdCtx, cancel := c.commandContext(ctx)
	defer cancel()
	return c.client.SetNX(cmdCtx, lockKey, token, c.lockTTL).Result()
}

func (c *redisACMECache) get(ctx context.Context, key string) ([]byte, error) {
	cmdCtx, cancel := c.commandContext(ctx)
	defer cancel()
	return c.client.Get(cmdCtx, key).Bytes()
}

func (c *redisACMECache) unlock(ctx context.Context, lockKey, token string) error {
	cmdCtx, cancel := c.commandContext(ctx)
	defer cancel()
	_, err := acmeUnlockScript.Run(cmdCtx, c.client, []string{lockKey}, token).Result()
	return err
}

func (c *redisACMECache) commandContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, c.operation)
}

func (c *redisACMECache) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *redisACMECache) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		leases := make(map[string]*acmeLease, len(c.leases))
		for key, lease := range c.leases {
			leases[key] = lease
			lease.cancel()
		}
		c.leases = make(map[string]*acmeLease)
		c.mu.Unlock()
		c.renewWaitGroup.Wait()
		for key, lease := range leases {
			_, lockKey := c.keys(key)
			_ = c.unlock(context.Background(), lockKey, lease.token)
		}
		if c.closer != nil {
			closeErr = c.closer.Close()
		}
	})
	return closeErr
}

func secureLeaseToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate ACME lease owner token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
