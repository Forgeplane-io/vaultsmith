package authn

import (
	"context"
	"fmt"
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
)

type RedisRuntime struct {
	pool         *redis.Pool
	sessionStore scs.Store
	synchronizer *redsync.Redsync
	config       config.RedisConfig
}

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

	runtime := &RedisRuntime{
		pool:         pool,
		sessionStore: redisstore.NewWithPrefix(pool, cfg.KeyPrefix+sessionKeySuffix),
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

func (r *RedisRuntime) NewRefreshMutex(sessionID string) *redsync.Mutex {
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
