package authn

import (
	"context"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alicebob/miniredis/v2"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/gomodule/redigo/redis"
)

func testRedisConfig(address string) config.RedisConfig {
	return config.RedisConfig{
		Address:          address,
		KeyPrefix:        "vaultsmith:test:",
		ConnectTimeout:   time.Second,
		ReadTimeout:      time.Second,
		WriteTimeout:     time.Second,
		PoolSize:         4,
		RefreshLockTTL:   200 * time.Millisecond,
		RefreshLockWait:  40 * time.Millisecond,
		RefreshLockRetry: 10 * time.Millisecond,
		ProviderTimeout:  100 * time.Millisecond,
	}
}

func newTestRedisRuntime(t *testing.T) (*miniredis.Miniredis, *RedisRuntime, config.RedisConfig) {
	t.Helper()
	server := miniredis.RunT(t)
	cfg := testRedisConfig(server.Addr())
	runtime, err := NewRedisRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return server, runtime, cfg
}

func TestRedisRuntimeProbeAndSessionPrefix(t *testing.T) {
	server, runtime, _ := newTestRedisRuntime(t)

	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	data, err := (scs.GobCodec{}).Encode(time.Now().Add(time.Minute), map[string]interface{}{})
	if err != nil {
		t.Fatalf("GobCodec.Encode() error = %v", err)
	}
	if err := runtime.SessionStore().Commit("token", data, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SessionStore().Commit() error = %v", err)
	}
	if !server.Exists("vaultsmith:test:session:token") {
		t.Fatalf("session key was not written with the configured prefix")
	}
}

func TestRedisSessionStoreRejectsMalformedSessionCommit(t *testing.T) {
	_, runtime, _ := newTestRedisRuntime(t)

	if err := runtime.SessionStore().Commit("token", []byte("malformed"), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("malformed session commit succeeded")
	}
}

func TestRedisSessionStoreReleasesFenceProbeBeforeCommit(t *testing.T) {
	server := miniredis.RunT(t)
	cfg := testRedisConfig(server.Addr())
	cfg.PoolSize = 1
	runtime, err := NewRedisRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	data, err := (scs.GobCodec{}).Encode(time.Now().Add(time.Minute), map[string]interface{}{})
	if err != nil {
		t.Fatalf("GobCodec.Encode() error = %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- runtime.SessionStore().Commit("token", data, time.Now().Add(time.Minute))
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("SessionStore().Commit() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SessionStore().Commit() blocked with a single pooled connection")
	}
}

func TestRedisRuntimeSupportsConfiguredAuthentication(t *testing.T) {
	server := miniredis.RunT(t)
	server.RequireAuth("redis-password")
	cfg := testRedisConfig(server.Addr())
	cfg.Password = "redis-password"

	runtime, err := NewRedisRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatalf("authenticated Probe() error = %v", err)
	}
}

func TestRedisRuntimeDoesNotDowngradeRejectedCredentials(t *testing.T) {
	server := miniredis.RunT(t)
	server.RequireAuth("expected-password")
	cfg := testRedisConfig(server.Addr())
	cfg.Password = "wrong-password"

	runtime, err := NewRedisRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	if err := runtime.Probe(context.Background()); err == nil {
		t.Fatal("Probe() error = nil, want configured credential rejection")
	}
}

func TestRedisRuntimeRefreshLockIsBoundedAndOwnerSafe(t *testing.T) {
	_, runtime, _ := newTestRedisRuntime(t)

	first := runtime.NewSessionMutex("session-id")
	if err := first.TryLockContext(context.Background()); err != nil {
		t.Fatalf("first TryLockContext() error = %v", err)
	}
	defer first.Unlock()

	second := runtime.NewSessionMutex("session-id")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := second.LockContext(ctx); err == nil {
		t.Fatal("second LockContext() error = nil, want bounded contention failure")
	}

	if unlocked, err := first.UnlockContext(context.Background()); err != nil || !unlocked {
		t.Fatalf("first UnlockContext() = (%t, %v), want true, nil", unlocked, err)
	}

	third := runtime.NewSessionMutex("session-id")
	if err := third.TryLockContext(context.Background()); err != nil {
		t.Fatalf("third TryLockContext() error = %v, lock was not released", err)
	}
	if unlocked, err := third.UnlockContext(context.Background()); err != nil || !unlocked {
		t.Fatalf("third UnlockContext() = (%t, %v), want true, nil", unlocked, err)
	}
}

func TestRedisRuntimeActivatesSessionFence(t *testing.T) {
	server, runtime, _ := newTestRedisRuntime(t)

	mutex := runtime.NewSessionMutex("session-id")
	if err := mutex.TryLockContext(context.Background()); err != nil {
		t.Fatalf("TryLockContext() error = %v", err)
	}
	defer mutex.Unlock()

	fence := mutex.Name() + fenceSeparator + mutex.Value()
	if err := runtime.ActivateSessionFence(context.Background(), "session-id", fence, time.Hour); err != nil {
		t.Fatalf("ActivateSessionFence() error = %v", err)
	}
	got, err := server.Get("vaultsmith:test:fence:session-id")
	if err != nil {
		t.Fatalf("read fence key: %v", err)
	}
	if got != fence {
		t.Fatalf("fence value = %q, want %q", got, fence)
	}
}

func TestRedisRuntimePoolRejectsConnectionErrors(t *testing.T) {
	server := miniredis.RunT(t)
	address := server.Addr()
	server.Close()
	cfg := testRedisConfig(address)
	runtime, err := NewRedisRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := runtime.Probe(ctx); err == nil {
		t.Fatal("Probe() error = nil, want connection failure")
	}

	conn := runtime.Pool().Get()
	defer conn.Close()
	if _, err := redis.String(conn.Do("PING")); err == nil {
		t.Fatal("pooled connection unexpectedly succeeded after failed probe")
	}
}
