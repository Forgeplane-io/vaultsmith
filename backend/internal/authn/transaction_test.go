package authn

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLoginTransactionIsAtomicAndSingleUse(t *testing.T) {
	_, runtime, _ := newTestRedisRuntime(t)
	const state = "state-1"
	transaction := LoginTransaction{
		Nonce:          "nonce-1",
		PKCEVerifier:   "verifier-1",
		PreAuthSession: "session-1",
		ReturnTo:       "/",
	}
	if err := runtime.SaveLoginTransaction(context.Background(), state, transaction); err != nil {
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
			consumed, found, err := runtime.ConsumeLoginTransaction(context.Background(), state)
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

func TestLoginTransactionRejectsDuplicateStateAndExpires(t *testing.T) {
	server, runtime, _ := newTestRedisRuntime(t)
	transaction := LoginTransaction{Nonce: "nonce"}
	if err := runtime.SaveLoginTransaction(context.Background(), "duplicate", transaction); err != nil {
		t.Fatalf("SaveLoginTransaction() error = %v", err)
	}
	if err := runtime.SaveLoginTransaction(context.Background(), "duplicate", transaction); err == nil {
		t.Fatal("second SaveLoginTransaction() error = nil, want duplicate rejection")
	}
	server.FastForward(loginTransactionLifetime + time.Millisecond)
	if _, found, err := runtime.ConsumeLoginTransaction(context.Background(), "duplicate"); err != nil || found {
		t.Fatalf("expired transaction = (found=%t, error=%v), want absent", found, err)
	}
}
