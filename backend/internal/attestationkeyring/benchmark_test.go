package attestationkeyring

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/forgeplane-io/vaultsmith/backend/internal/attestation"
)

func writeBenchmarkKeyring(b *testing.B, path string, data []byte) {
	b.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkKeyringReloadUnderTraffic(b *testing.B) {
	keyA := makeTestKey("benchmark-a", StateActive, 11)
	keyB := makeTestKey("benchmark-b", StateActive, 12)
	path := filepath.Join(b.TempDir(), "keyring.json")
	writeBenchmarkKeyring(b, path, makeKeyringJSON(keyA.id, keyA))
	manager, err := NewManager(path, testIssuer)
	if err != nil {
		b.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var traffic sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		traffic.Add(1)
		go func() {
			defer traffic.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_, _ = manager.Resolve(testIssuer, keyA.id)
					_, _ = manager.Sign(testClaims(testIssuer))
				}
			}
		}()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if iteration%2 == 0 {
			writeBenchmarkKeyring(b, path, makeKeyringJSON(keyA.id, keyA, makeTestKey(keyB.id, StateRetired, 12)))
		} else {
			writeBenchmarkKeyring(b, path, makeKeyringJSON(keyB.id, keyB, makeTestKey(keyA.id, StateRetired, 11)))
		}
		if err := manager.Reload(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	cancel()
	traffic.Wait()
}

func BenchmarkLargeRetiredKeySet(b *testing.B) {
	entries := make([]testKey, 0, MaxEntries)
	for index := 0; index < MaxEntries-1; index++ {
		entries = append(entries, makeTestKey("retired-key", StateRetired, byte(index+1)))
		entries[index].id = "retired-key-" + string(rune('a'+index/26)) + string(rune('a'+index%26))
	}
	active := makeTestKey("benchmark-active", StateActive, 250)
	entries = append(entries, active)
	snapshot, err := Parse(makeKeyringJSON(active.id, entries...), testIssuer)
	if err != nil {
		b.Fatal(err)
	}
	retired := entries[len(entries)-2]
	signed, err := attestation.Sign(testClaims(testIssuer), retired.id, ed25519.NewKeyFromSeed(retired.seed))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.Run("historical-verification", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := attestation.Verify(signed, attestation.VerifyOptions{
				ExpectedIssuer: testIssuer,
				Resolver:       snapshot,
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("public-discovery", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := snapshot.JWKSJSON(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkConcurrentVerification(b *testing.B) {
	key := makeTestKey("concurrent-key", StateActive, 33)
	path := filepath.Join(b.TempDir(), "keyring.json")
	writeBenchmarkKeyring(b, path, makeKeyringJSON(key.id, key))
	manager, err := NewManager(path, testIssuer)
	if err != nil {
		b.Fatal(err)
	}
	signed, err := manager.Sign(testClaims(testIssuer))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	var failed atomic.Bool
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := attestation.Verify(signed, attestation.VerifyOptions{
				ExpectedIssuer: testIssuer,
				Resolver:       manager,
			}); err != nil {
				failed.Store(true)
				return
			}
		}
	})
	if failed.Load() {
		b.Fatal("concurrent verification failed")
	}
}
