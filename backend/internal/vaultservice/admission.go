package vaultservice

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

var (
	ErrAdmissionSaturated          = errors.New("operation admission is saturated")
	ErrVerifierAdmissionSaturated  = errors.New("attestation verification admission is saturated")
	ErrAttestationVerificationBusy = ErrVerifierAdmissionSaturated
)

// MaxRuntimeAdmissionCapacity is the contract's pre-benchmark upper bound.
// Phase 3 can select a lower compiled cap from the 2 GiB benchmark, but never a
// higher one without revising that reviewed budget.
const MaxRuntimeAdmissionCapacity = 16

// MaxVerifierAdmissionCapacity is the fixed upper bound for verification
// work. Verification has a smaller budget than Vault operations because the
// request can retain two bounded Vault envelopes while parsing and checking a
// proof.
const MaxVerifierAdmissionCapacity = 8

// Admission bounds concurrent request-body retention and vault work. Phase 2
// provisions up to one slot per schedulable Go CPU, subject to the reviewed
// safety tripwire. Capacity() and Rejections() expose the configured limit and
// pressure so the Phase 3 benchmark can select a lower compiled cap.
type Admission struct {
	tokens     chan struct{}
	inUse      atomic.Int64
	rejections atomic.Uint64
	saturated  error
}

type Lease struct {
	state *leaseState
}

// VerifierAdmission and VerifierLease are aliases of the same nonblocking
// token implementation used by operation admission. They are deliberately
// separate instances, so verification pressure cannot consume rotation slots.
type VerifierAdmission = Admission
type VerifierLease = Lease

type leaseState struct {
	admission     *Admission
	mu            sync.Mutex
	active        bool
	binding       *leaseContextBinding
	boundContext  context.Context
	contextIssued bool
}

type leaseContextKey struct{}

type leaseContextBinding struct {
	state  *leaseState
	origin context.Context
}

func NewAdmission(capacity int) (*Admission, error) {
	return newAdmission(capacity, ErrAdmissionSaturated)
}

func newAdmission(capacity int, saturated error) (*Admission, error) {
	if capacity < 1 {
		return nil, fmt.Errorf("admission capacity must be positive")
	}
	if saturated == nil {
		saturated = ErrAdmissionSaturated
	}
	return &Admission{tokens: make(chan struct{}, capacity), saturated: saturated}, nil
}

func NewRuntimeAdmission() *Admission {
	capacity := runtimeAdmissionCapacity(runtime.GOMAXPROCS(0))
	admission, _ := NewAdmission(capacity)
	return admission
}

// NewVerifierAdmission constructs a separate nonblocking admission pool for
// attestation verification.
func NewVerifierAdmission(capacity int) (*VerifierAdmission, error) {
	return newAdmission(capacity, ErrVerifierAdmissionSaturated)
}

// NewRuntimeVerifierAdmission uses the bounded verifier capacity derived from
// the current schedulable CPU count.
func NewRuntimeVerifierAdmission() *VerifierAdmission {
	capacity := verifierAdmissionCapacity(runtime.GOMAXPROCS(0))
	admission, _ := NewVerifierAdmission(capacity)
	return admission
}

func runtimeAdmissionCapacity(gomaxprocs int) int {
	if gomaxprocs < 1 {
		return 1
	}
	if gomaxprocs > MaxRuntimeAdmissionCapacity {
		return MaxRuntimeAdmissionCapacity
	}
	return gomaxprocs
}

func verifierAdmissionCapacity(gomaxprocs int) int {
	if gomaxprocs < 1 {
		return 1
	}
	if gomaxprocs > MaxVerifierAdmissionCapacity {
		return MaxVerifierAdmissionCapacity
	}
	return gomaxprocs
}

func (a *Admission) TryAcquire(ctx context.Context) (*Lease, error) {
	if a == nil {
		return nil, fmt.Errorf("admission is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case a.tokens <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-a.tokens
			return nil, err
		}
		a.inUse.Add(1)
		state := &leaseState{admission: a, active: true}
		lease := &Lease{state: state}
		binding := &leaseContextBinding{state: state, origin: ctx}
		state.binding = binding
		state.boundContext = context.WithValue(ctx, leaseContextKey{}, binding)
		return lease, nil
	default:
		a.rejections.Add(1)
		if a.saturated != nil {
			return nil, a.saturated
		}
		return nil, ErrAdmissionSaturated
	}
}

func (l *Lease) Release() {
	if l == nil || l.state == nil || l.state.admission == nil {
		return
	}
	state := l.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active {
		return
	}
	state.active = false
	<-state.admission.tokens
	state.admission.inUse.Add(-1)
}

// Context exposes the immutable acquisition context with the lease binding.
// The first call cannot replace the request origin; later calls only preserve a
// context that already carries this exact lease binding.
func (l *Lease) Context(ctx context.Context) context.Context {
	if l == nil || l.state == nil || ctx == nil {
		return ctx
	}
	state := l.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.binding == nil || state.boundContext == nil {
		return ctx
	}
	if existing := leaseBindingFromContext(ctx); existing == state.binding && state.contextIssued {
		return ctx
	}
	if state.contextIssued {
		return ctx
	}
	state.contextIssued = true
	return state.boundContext
}

func (a *Admission) Capacity() int {
	if a == nil {
		return 0
	}
	return cap(a.tokens)
}

func (a *Admission) InUse() int {
	if a == nil {
		return 0
	}
	return int(a.inUse.Load())
}

func (a *Admission) Rejections() uint64 {
	if a == nil {
		return 0
	}
	return a.rejections.Load()
}

func leaseFromContext(ctx context.Context) *Lease {
	binding := leaseBindingFromContext(ctx)
	if binding == nil || binding.state == nil {
		return nil
	}
	return &Lease{state: binding.state}
}

func leaseBindingFromContext(ctx context.Context) *leaseContextBinding {
	if ctx == nil {
		return nil
	}
	binding, _ := ctx.Value(leaseContextKey{}).(*leaseContextBinding)
	return binding
}

func contextCancellation(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return err
	}
	return nil
}

func (l *Lease) contextErr(ctx context.Context) error {
	if err := contextCancellation(ctx); err != nil {
		return err
	}
	if l == nil || l.state == nil {
		return nil
	}
	binding := leaseBindingFromContext(ctx)
	if binding == nil || binding.state != l.state || binding.origin == nil {
		return nil
	}
	return contextCancellation(binding.origin)
}

func (l *Lease) liveForContext(ctx context.Context, admission *Admission) bool {
	binding := leaseBindingFromContext(ctx)
	if l == nil || l.state == nil || l.state.admission != admission || binding == nil || binding.state != l.state {
		return false
	}
	state := l.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.active && state.contextIssued && state.binding == binding
}

func (l *Lease) executionContext() context.Context {
	if l == nil || l.state == nil {
		return nil
	}
	state := l.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || !state.contextIssued {
		return nil
	}
	return state.boundContext
}

func (l *Lease) holdForContext(ctx context.Context, admission *Admission) bool {
	binding := leaseBindingFromContext(ctx)
	if l == nil || l.state == nil || l.state.admission != admission || binding == nil || binding.state != l.state {
		return false
	}
	state := l.state
	state.mu.Lock()
	if !state.active || !state.contextIssued || state.binding != binding {
		state.mu.Unlock()
		return false
	}
	return true
}

func (l *Lease) releaseHold() {
	if l != nil && l.state != nil {
		l.state.mu.Unlock()
	}
}
