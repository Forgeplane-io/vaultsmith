package authn

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redsync/redsync/v4"
)

type sessionLockContextKey struct{}

type sessionLockState struct {
	token   string
	fence   string
	healthy func() bool
}

type sessionLockHandle struct {
	ctx     context.Context
	unlock  func()
	fence   string
	healthy func() bool
}

type sessionLockLease struct {
	mutex  *redsync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	lost   atomic.Bool
}

func (lease *sessionLockLease) keepAlive(ttl, timeout time.Duration) {
	defer close(lease.done)
	interval := ttl / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx := lease.ctx
			cancel := func() {}
			if timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, timeout)
			}
			ok, err := lease.mutex.ExtendContext(ctx)
			cancel()
			if err != nil || !ok {
				lease.lost.Store(true)
				if lease.cancel != nil {
					lease.cancel()
				}
				return
			}
		case <-lease.stop:
			return
		}
	}
}

func (lease *sessionLockLease) healthy() bool {
	return !lease.lost.Load()
}

func (lease *sessionLockLease) release() {
	lease.once.Do(func() {
		close(lease.stop)
		if lease.cancel != nil {
			lease.cancel()
		}
		<-lease.done
		_, _ = lease.mutex.UnlockContext(context.Background())
	})
}

func sessionTokenFromRequest(r *http.Request, cookieName string) string {
	if r == nil || cookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func sessionLockContextState(ctx context.Context) *sessionLockState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(sessionLockContextKey{}).(*sessionLockState)
	return state
}

func sessionLockStateFromContext(ctx context.Context, token string) (*sessionLockState, bool) {
	if token == "" {
		return nil, false
	}
	state := sessionLockContextState(ctx)
	return state, state != nil && state.token == token
}

func sessionLockHealthy(ctx context.Context) bool {
	state := sessionLockContextState(ctx)
	if state == nil || state.healthy == nil {
		return true
	}
	return state.healthy()
}

func sessionLockFence(ctx context.Context) string {
	state := sessionLockContextState(ctx)
	if state == nil {
		return ""
	}
	return state.fence
}

func withSessionLock(ctx context.Context, token, fence string, healthy func() bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if token == "" {
		return ctx
	}
	if healthy == nil {
		healthy = func() bool { return true }
	}
	return context.WithValue(ctx, sessionLockContextKey{}, &sessionLockState{token: token, fence: fence, healthy: healthy})
}

func rebindSessionLock(ctx context.Context, token string) {
	if ctx == nil || token == "" {
		return
	}
	state := sessionLockContextState(ctx)
	if state != nil {
		state.token = token
	}
}

func (a *Authenticator) acquireSessionLock(ctx context.Context, token string) (sessionLockHandle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if state, ok := sessionLockStateFromContext(ctx, token); ok {
		return sessionLockHandle{ctx: ctx, fence: state.fence, healthy: state.healthy}, nil
	}
	if a == nil || a.Redis == nil || token == "" {
		return sessionLockHandle{ctx: ctx, healthy: func() bool { return true }}, nil
	}

	lockCtx, cancel := context.WithCancel(ctx)
	waitCtx, waitCancel := context.WithTimeout(lockCtx, a.Config.Redis.RefreshLockWait)
	defer waitCancel()
	mutex := a.Redis.NewSessionMutex(token)
	if err := mutex.LockContext(waitCtx); err != nil {
		cancel()
		return sessionLockHandle{}, ErrTemporaryUnavailable
	}
	fence := mutex.Name() + fenceSeparator + mutex.Value()
	if err := a.Redis.ActivateSessionFence(lockCtx, token, fence, a.Config.Session.AbsoluteLifetime); err != nil {
		_, _ = mutex.UnlockContext(context.Background())
		cancel()
		return sessionLockHandle{}, ErrTemporaryUnavailable
	}
	lease := &sessionLockLease{
		mutex:  mutex,
		ctx:    lockCtx,
		cancel: cancel,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go lease.keepAlive(a.Config.Redis.RefreshLockTTL, a.Config.Redis.WriteTimeout)
	return sessionLockHandle{ctx: lockCtx, unlock: lease.release, fence: fence, healthy: lease.healthy}, nil
}

func (handle sessionLockHandle) release() {
	if handle.unlock != nil {
		handle.unlock()
	}
}
