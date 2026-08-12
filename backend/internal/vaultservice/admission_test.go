package vaultservice

import (
	"context"
	"errors"
	"testing"
)

func TestAdmissionIsNonBlockingAndReleasesCapacity(t *testing.T) {
	admission, err := NewAdmission(1)
	if err != nil {
		t.Fatalf("NewAdmission() error = %v", err)
	}
	first, err := admission.TryAcquire(context.Background())
	if err != nil {
		t.Fatalf("first TryAcquire() error = %v", err)
	}
	if admission.Capacity() != 1 || admission.InUse() != 1 {
		t.Fatalf("admission capacity/in-use = %d/%d, want 1/1", admission.Capacity(), admission.InUse())
	}
	if _, err := admission.TryAcquire(context.Background()); !errors.Is(err, ErrAdmissionSaturated) {
		t.Fatalf("saturated TryAcquire() error = %v, want ErrAdmissionSaturated", err)
	}
	if admission.Rejections() != 1 {
		t.Fatalf("rejections = %d, want 1", admission.Rejections())
	}

	first.Release()
	first.Release()
	if admission.InUse() != 0 {
		t.Fatalf("in-use after release = %d, want 0", admission.InUse())
	}
	second, err := admission.TryAcquire(context.Background())
	if err != nil {
		t.Fatalf("TryAcquire() after release error = %v", err)
	}
	second.Release()
}

func TestAdmissionRejectsInvalidCapacityAndCanceledContext(t *testing.T) {
	if _, err := NewAdmission(0); err == nil {
		t.Fatal("NewAdmission(0) unexpectedly succeeded")
	}
	admission, err := NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admission.TryAcquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("TryAcquire(canceled) error = %v, want context.Canceled", err)
	}
	if admission.InUse() != 0 || admission.Rejections() != 0 {
		t.Fatalf("canceled acquisition changed counters: in-use=%d rejections=%d", admission.InUse(), admission.Rejections())
	}
}

func TestLeaseContextCannotReplaceAcquisitionOrigin(t *testing.T) {
	tests := map[string]func(context.Context) context.Context{
		"background":     func(context.Context) context.Context { return context.Background() },
		"without cancel": context.WithoutCancel,
	}
	for name, detach := range tests {
		t.Run(name, func(t *testing.T) {
			admission, err := NewAdmission(1)
			if err != nil {
				t.Fatal(err)
			}
			origin, cancel := context.WithCancel(context.Background())
			lease, err := admission.TryAcquire(origin)
			if err != nil {
				t.Fatal(err)
			}
			bound := lease.Context(detach(origin))
			cancel()
			if !errors.Is(bound.Err(), context.Canceled) {
				lease.Release()
				t.Fatalf("bound context error = %v, want context.Canceled", bound.Err())
			}
			lease.Release()
			if admission.InUse() != 0 {
				t.Fatalf("admission in use = %d, want 0", admission.InUse())
			}
		})
	}
}

func TestRuntimeAdmissionCapacityUsesCPUCountWithinSafetyTripwire(t *testing.T) {
	tests := map[int]int{
		0:  1,
		1:  1,
		4:  4,
		16: 16,
		64: 16,
	}
	for gomaxprocs, want := range tests {
		if got := runtimeAdmissionCapacity(gomaxprocs); got != want {
			t.Fatalf("runtimeAdmissionCapacity(%d) = %d, want %d", gomaxprocs, got, want)
		}
	}
}
