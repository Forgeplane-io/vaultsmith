package authn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/scs/redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/go-redsync/redsync/v4"
	redsyncredigo "github.com/go-redsync/redsync/v4/redis/redigo"
	"github.com/gomodule/redigo/redis"
)

const (
	sessionKeySuffix     = "session:"
	transactionKeySuffix = "transaction:"
	lockKeySuffix        = "lock:"
	fenceKeySuffix       = "fence:"
	fenceSeparator       = "\x00"
)

type RedisRuntime struct {
	pool         *redis.Pool
	sessionStore scs.Store
	synchronizer *redsync.Redsync
	config       config.RedisConfig
}

type fencedSessionStore struct {
	base       scs.Store
	pool       *redis.Pool
	codec      scs.Codec
	prefix     string
	hashTokens bool
}

func (store *fencedSessionStore) SetCodec(codec scs.Codec) {
	store.codec = codec
}

func (store *fencedSessionStore) SetHashTokenInStore(enabled bool) {
	store.hashTokens = enabled
}

func (store *fencedSessionStore) Find(token string) ([]byte, bool, error) {
	return store.base.Find(token)
}

func (store *fencedSessionStore) Commit(token string, data []byte, expiry time.Time) error {
	fence, ok, err := store.fenceFromSession(data)
	if err != nil {
		return err
	}
	if !ok {
		fenceErr := func() error {
			conn := store.pool.Get()
			defer conn.Close()
			_, err := redis.String(conn.Do("GET", store.fenceKey(token)))
			return err
		}()
		if fenceErr == redis.ErrNil {
			return store.base.Commit(token, data, expiry)
		} else if fenceErr != nil {
			return fenceErr
		}
		return ErrTemporaryUnavailable
	}
	lockKey, owner, valid := parseSessionFence(fence)
	if !valid {
		return ErrTemporaryUnavailable
	}

	conn := store.pool.Get()
	defer conn.Close()
	resultValue, err := conn.Do("EVAL", fencedCommitScript, 3,
		store.sessionKey(token), lockKey, store.fenceKey(token),
		data, fence, owner, expiry.UnixNano()/int64(time.Millisecond))
	if err != nil {
		return err
	}
	result, err := redis.Int(resultValue, nil)
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrTemporaryUnavailable
	}
	return nil
}

func (store *fencedSessionStore) Delete(token string) error {
	conn := store.pool.Get()
	defer conn.Close()
	if _, err := redis.String(conn.Do("GET", store.fenceKey(token))); err == redis.ErrNil {
		return ErrTemporaryUnavailable
	} else if err != nil {
		return err
	}
	return ErrTemporaryUnavailable
}

// DeleteCtx lets SCS pass the request context through token rotation and
// destruction, preserving the lock fence that authorized the delete.
func (store *fencedSessionStore) DeleteCtx(ctx context.Context, token string) error {
	fence := sessionLockFence(ctx)
	if fence == "" {
		return store.Delete(token)
	}
	return store.deleteWithFence(ctx, token, fence)
}

func (store *fencedSessionStore) deleteWithFence(ctx context.Context, token, fence string) error {
	lockKey, owner, valid := parseSessionFence(fence)
	if !valid {
		return ErrTemporaryUnavailable
	}
	conn, err := store.pool.GetContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	result, err := redis.Int(conn.Do("EVAL", fencedDeleteExpectedScript, 3,
		store.sessionKey(token), store.fenceKey(token), lockKey, fence, owner))
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrTemporaryUnavailable
	}
	return nil
}

func (store *fencedSessionStore) Activate(ctx context.Context, token, fence string, ttl time.Duration) error {
	lockKey, owner, valid := parseSessionFence(fence)
	if !valid {
		return ErrTemporaryUnavailable
	}
	conn, err := store.pool.GetContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	expiry := int64(0)
	if ttl > 0 {
		expiry = int64(ttl / time.Millisecond)
		if expiry < 1 {
			expiry = 1
		}
	}
	result, err := redis.Int(conn.Do("EVAL", fencedActivateScript, 2,
		lockKey, store.fenceKeyForSessionToken(token), owner, fence, expiry))
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrTemporaryUnavailable
	}
	return nil
}

func (store *fencedSessionStore) fenceFromSession(data []byte) (string, bool, error) {
	codec := store.codec
	if codec == nil {
		codec = scs.GobCodec{}
	}
	_, values, err := codec.Decode(data)
	if err != nil {
		return "", false, err
	}
	fence, ok := values[sessionFenceKey].(string)
	return fence, ok && fence != "", nil
}

func (store *fencedSessionStore) sessionKey(token string) string {
	return store.prefix + sessionKeySuffix + token
}

func (store *fencedSessionStore) fenceKey(token string) string {
	return store.prefix + fenceKeySuffix + token
}

func (store *fencedSessionStore) fenceKeyForSessionToken(token string) string {
	if store.hashTokens {
		hash := sha256.Sum256([]byte(token))
		token = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	return store.fenceKey(token)
}

func parseSessionFence(fence string) (string, string, bool) {
	lockKey, owner, ok := strings.Cut(fence, fenceSeparator)
	return lockKey, owner, ok && lockKey != "" && owner != ""
}

const fencedActivateScript = `
local owner = redis.call("GET", KEYS[1])
if owner ~= ARGV[1] then return 0 end
if tonumber(ARGV[3]) > 0 then
  redis.call("SET", KEYS[2], ARGV[2], "PX", ARGV[3])
else
  redis.call("SET", KEYS[2], ARGV[2])
end
return 1
`

const fencedCommitScript = `
if redis.call("GET", KEYS[2]) ~= ARGV[3] then return 0 end
if redis.call("GET", KEYS[3]) ~= ARGV[2] then return 0 end
redis.call("SET", KEYS[1], ARGV[1])
redis.call("PEXPIREAT", KEYS[1], ARGV[4])
redis.call("SET", KEYS[3], ARGV[2])
redis.call("PEXPIREAT", KEYS[3], ARGV[4])
return 1
`

const fencedDeleteExpectedScript = `
if redis.call("GET", KEYS[2]) ~= ARGV[1] then return 0 end
if redis.call("GET", KEYS[3]) ~= ARGV[2] then return 0 end
redis.call("DEL", KEYS[1], KEYS[2])
return 1
`

func NewRedisRuntime(cfg config.RedisConfig) (*RedisRuntime, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("redis address is required")
	}
	if cfg.KeyPrefix == "" {
		return nil, fmt.Errorf("redis key prefix is required")
	}
	if cfg.RefreshLockTTL <= cfg.ProviderTimeout {
		return nil, fmt.Errorf("redis refresh lock TTL must exceed provider timeout")
	}
	if cfg.RefreshLockWait <= 0 || cfg.RefreshLockRetry <= 0 {
		return nil, fmt.Errorf("redis refresh lock wait and retry must be positive")
	}

	dialOptions := redisDialOptions(cfg)
	pool := &redis.Pool{
		MaxIdle:         cfg.PoolSize,
		MaxActive:       cfg.PoolSize,
		Wait:            true,
		IdleTimeout:     5 * time.Minute,
		MaxConnLifetime: 30 * time.Minute,
		DialContext: func(ctx context.Context) (redis.Conn, error) {
			return redis.DialContext(ctx, "tcp", cfg.Address, dialOptions...)
		},
		TestOnBorrowContext: func(ctx context.Context, conn redis.Conn, lastUsed time.Time) error {
			if time.Since(lastUsed) < time.Minute {
				return nil
			}
			_, err := conn.Do("PING")
			return err
		},
	}

	store := &fencedSessionStore{
		base:   redisstore.NewWithPrefix(pool, cfg.KeyPrefix+sessionKeySuffix),
		pool:   pool,
		codec:  scs.GobCodec{},
		prefix: cfg.KeyPrefix,
	}
	runtime := &RedisRuntime{
		pool:         pool,
		sessionStore: store,
		synchronizer: redsync.New(redsyncredigo.NewPool(pool)),
		config:       cfg,
	}
	return runtime, nil
}

func redisDialOptions(cfg config.RedisConfig) []redis.DialOption {
	options := []redis.DialOption{
		redis.DialConnectTimeout(cfg.ConnectTimeout),
		redis.DialReadTimeout(cfg.ReadTimeout),
		redis.DialWriteTimeout(cfg.WriteTimeout),
		redis.DialDatabase(cfg.Database),
	}
	if cfg.Username != "" {
		options = append(options, redis.DialUsername(cfg.Username), redis.DialPassword(cfg.Password))
	} else if cfg.Password != "" {
		options = append(options, redis.DialPassword(cfg.Password))
	}
	if cfg.TLS {
		options = append(options, redis.DialUseTLS(true))
	}
	return options
}

func (r *RedisRuntime) Probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := r.pool.GetContext(ctx)
	if err != nil {
		return fmt.Errorf("redis probe connection failed: %w", err)
	}
	defer conn.Close()
	pong, err := redis.String(conn.Do("PING"))
	if err != nil {
		return fmt.Errorf("redis probe failed: %w", err)
	}
	if pong != "PONG" {
		return fmt.Errorf("redis probe returned unexpected response")
	}
	return nil
}

func (r *RedisRuntime) Pool() *redis.Pool {
	return r.pool
}

func (r *RedisRuntime) SessionStore() scs.Store {
	return r.sessionStore
}

func (r *RedisRuntime) TransactionPrefix() string {
	return r.config.KeyPrefix + transactionKeySuffix
}

func (r *RedisRuntime) ActivateSessionFence(ctx context.Context, token, fence string, ttl time.Duration) error {
	store, ok := r.sessionStore.(*fencedSessionStore)
	if !ok {
		return ErrTemporaryUnavailable
	}
	return store.Activate(ctx, token, fence, ttl)
}

func (r *RedisRuntime) NewSessionMutex(sessionID string) *redsync.Mutex {
	tries := int(r.config.RefreshLockWait/r.config.RefreshLockRetry) + 1
	return r.synchronizer.NewMutex(
		r.config.KeyPrefix+lockKeySuffix+sessionID,
		redsync.WithExpiry(r.config.RefreshLockTTL),
		redsync.WithTries(tries),
		redsync.WithRetryDelay(r.config.RefreshLockRetry),
	)
}

func (r *RedisRuntime) Close() error {
	return r.pool.Close()
}
