package authn

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/go-redsync/redsync/v4"
)

type sessionLockContextKey struct{}

type sessionLockState struct {
	token string
}

type sessionLockLease struct {
	mutex *redsync.Mutex
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
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
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				ok, err := lease.mutex.ExtendContext(ctx)
				cancel()
				if err != nil || !ok {
					return
				}
			} else if ok, err := lease.mutex.ExtendContext(ctx); err != nil || !ok {
				return
			}
		case <-lease.stop:
			return
		}
	}
}

func (lease *sessionLockLease) release() {
	lease.once.Do(func() {
		close(lease.stop)
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

func sessionLockHeld(ctx context.Context, token string) bool {
	if ctx == nil || token == "" {
		return false
	}
	state, ok := ctx.Value(sessionLockContextKey{}).(sessionLockState)
	return ok && state.token == token
}

func withSessionLock(ctx context.Context, token string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, sessionLockContextKey{}, sessionLockState{token: token})
}

func (a *Authenticator) acquireSessionLock(ctx context.Context, token string) (func(), error) {
	if a == nil || a.Redis == nil || token == "" || sessionLockHeld(ctx, token) {
		return func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lockCtx, cancel := context.WithTimeout(ctx, a.Config.Redis.RefreshLockWait)
	defer cancel()
	mutex := a.Redis.NewSessionMutex(token)
	if err := mutex.LockContext(lockCtx); err != nil {
		return nil, ErrTemporaryUnavailable
	}
	lease := &sessionLockLease{mutex: mutex, stop: make(chan struct{}), done: make(chan struct{})}
	go lease.keepAlive(a.Config.Redis.RefreshLockTTL, a.Config.Redis.WriteTimeout)
	return lease.release, nil
}
