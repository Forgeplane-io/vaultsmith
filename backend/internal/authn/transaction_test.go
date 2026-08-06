package authn

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLoginTransactionIsAtomicAndSingleUse(t *testing.T) {
	_, runtime, _ := newTestRedisRuntime(t)

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
	type consumeResult struct {
		transaction LoginTransaction
		found       bool
	}
	results := make(chan consumeResult, consumers)
	for range consumers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, found, err := runtime.ConsumeLoginTransaction(context.Background(), transaction.State)
			if err != nil {
				t.Errorf("ConsumeLoginTransaction() error = %v", err)
				return
			}
			results <- consumeResult{transaction: consumed, found: found}
		}()
	}
	wg.Wait()
	close(results)

	foundCount := 0
	var got LoginTransaction
	for result := range results {
		if result.found {
			foundCount++
			got = result.transaction
		}
	}
	if foundCount != 1 {
		t.Fatalf("successful transaction consumers = %d, want 1", foundCount)
	}
	if got.Nonce != transaction.Nonce || got.PKCEVerifier != transaction.PKCEVerifier || got.PreAuthSession != transaction.PreAuthSession || got.ReturnTo != transaction.ReturnTo {
		t.Fatalf("consumed transaction payload = %#v, want %#v", got, transaction)
	}
}

func TestLoginTransactionRejectsDuplicateStateAndExpiredValues(t *testing.T) {
	_, runtime, _ := newTestRedisRuntime(t)

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
