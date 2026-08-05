package authn

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestLoginTransactionIsAtomicAndSingleUse(t *testing.T) {
	server := miniredis.RunT(t)
	runtime, err := NewRedisRuntime(testRedisConfig(server.Addr()))
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	transaction := LoginTransaction{
		State:          "state-1",
		Nonce:          "nonce-1",
		PKCEVerifier:   "verifier-1",
		PreAuthSession: "session-1",
		ReturnTo:       "/",
		ExpiresAt:      time.Now().Add(time.Minute),
	}
	if err := runtime.SaveLoginTransaction(context.Background(), transaction); err != nil {
		t.Fatalf("SaveLoginTransaction() error = %v", err)
	}

	const consumers = 8
	var wg sync.WaitGroup
	results := make(chan bool, consumers)
	for range consumers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, found, err := runtime.ConsumeLoginTransaction(context.Background(), transaction.State)
			if err != nil {
				t.Errorf("ConsumeLoginTransaction() error = %v", err)
				return
			}
			results <- found
		}()
	}
	wg.Wait()
	close(results)

	foundCount := 0
	for found := range results {
		if found {
			foundCount++
		}
	}
	if foundCount != 1 {
		t.Fatalf("successful transaction consumers = %d, want 1", foundCount)
	}
}

func TestLoginTransactionRejectsDuplicateStateAndExpiredValues(t *testing.T) {
	server := miniredis.RunT(t)
	runtime, err := NewRedisRuntime(testRedisConfig(server.Addr()))
	if err != nil {
		t.Fatalf("NewRedisRuntime() error = %v", err)
	}
	defer runtime.Close()

	transaction := LoginTransaction{State: "duplicate", ExpiresAt: time.Now().Add(time.Minute)}
	if err := runtime.SaveLoginTransaction(context.Background(), transaction); err != nil {
		t.Fatalf("SaveLoginTransaction() error = %v", err)
	}
	if err := runtime.SaveLoginTransaction(context.Background(), transaction); err == nil {
		t.Fatal("second SaveLoginTransaction() error = nil, want duplicate rejection")
	}

	expired := LoginTransaction{State: "expired", ExpiresAt: time.Now().Add(-time.Second)}
	if err := runtime.SaveLoginTransaction(context.Background(), expired); err == nil {
		t.Fatal("expired SaveLoginTransaction() error = nil, want expiry rejection")
	}
}
