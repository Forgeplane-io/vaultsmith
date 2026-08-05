package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gomodule/redigo/redis"
)

const loginTransactionLifetime = 10 * time.Minute

var consumeLoginTransactionScript = redis.NewScript(1, `
local value = redis.call("GET", KEYS[1])
if not value then
  return false
end
redis.call("DEL", KEYS[1])
return value
`)

type LoginTransaction struct {
	State          string    `json:"state"`
	Nonce          string    `json:"nonce"`
	PKCEVerifier   string    `json:"pkce_verifier"`
	PreAuthSession string    `json:"pre_auth_session"`
	ReturnTo       string    `json:"return_to"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (r *RedisRuntime) SaveLoginTransaction(ctx context.Context, transaction LoginTransaction) error {
	if transaction.State == "" {
		return fmt.Errorf("login transaction state is required")
	}
	if transaction.ExpiresAt.IsZero() {
		transaction.ExpiresAt = time.Now().Add(loginTransactionLifetime)
	}
	ttl := time.Until(transaction.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("login transaction is expired")
	}
	payload, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("encode login transaction: %w", err)
	}
	conn, err := r.pool.GetContext(ctx)
	if err != nil {
		return fmt.Errorf("login transaction connection failed: %w", err)
	}
	defer conn.Close()
	key := r.TransactionPrefix() + transaction.State
	reply, err := redis.String(conn.Do("SET", key, payload, "NX", "PX", ttl.Milliseconds()))
	if err != nil {
		return fmt.Errorf("save login transaction: %w", err)
	}
	if reply != "OK" {
		return fmt.Errorf("login transaction already exists")
	}
	return nil
}

func (r *RedisRuntime) ConsumeLoginTransaction(ctx context.Context, state string) (LoginTransaction, bool, error) {
	if state == "" {
		return LoginTransaction{}, false, nil
	}
	conn, err := r.pool.GetContext(ctx)
	if err != nil {
		return LoginTransaction{}, false, fmt.Errorf("login transaction connection failed: %w", err)
	}
	defer conn.Close()
	raw, err := redis.Bytes(consumeLoginTransactionScript.Do(conn, r.TransactionPrefix()+state))
	if err == redis.ErrNil {
		return LoginTransaction{}, false, nil
	}
	if err != nil {
		return LoginTransaction{}, false, fmt.Errorf("consume login transaction: %w", err)
	}
	var transaction LoginTransaction
	if err := json.Unmarshal(raw, &transaction); err != nil {
		return LoginTransaction{}, false, fmt.Errorf("decode login transaction: %w", err)
	}
	if transaction.State != state || time.Now().After(transaction.ExpiresAt) {
		return LoginTransaction{}, false, nil
	}
	return transaction, true, nil
}
