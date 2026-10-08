package authn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// Persisted data is a trust boundary: no legacy adoption, foreign identity,
// early-return bypass, or refresh-before-validation is permitted.
func TestAuthenticatedPrincipalSessionBoundary(t *testing.T) {
	for _, path := range []string{"fresh", "retry", "refresh"} {
		for _, change := range []string{"unchanged", "issuer", "client", "resource", "legacy", "previous-version", "malformed", "unknown-version", "principal-issuer"} {
			t.Run(path+"/"+change, func(t *testing.T) {
				calls := 0
				service, token := newRefreshService(t, func(context.Context, string) (*oauth2.Token, error) {
					calls++
					return &oauth2.Token{Expiry: time.Now().Add(time.Hour)}, nil
				})
				ctx := mustLoadSession(t, service.Sessions, token)
				switch path {
				case "fresh":
					service.Sessions.Put(ctx, sessionExpiresAtKey, time.Now().Add(time.Hour))
				case "retry":
					service.Sessions.Put(ctx, sessionRefreshCheckedKey, time.Now())
				}
				switch change {
				case "issuer":
					service.Config.OIDC.IssuerURL = "https://other-issuer.example"
				case "client":
					service.Config.OIDC.ClientID = "other-client"
				case "resource":
					service.Config.OIDC.PublicBaseURL = "https://other-vault.example"
				case "legacy":
					service.Sessions.Remove(ctx, "auth.binding")
				case "previous-version":
					binding := service.Sessions.GetString(ctx, sessionBindingKey)
					_, digest, _ := strings.Cut(binding, ":")
					service.Sessions.Put(ctx, sessionBindingKey, "v1:"+digest)
					// OAuth-only refresh in the previous version could already
					// have overwritten the original verified claim deadline.
					service.Sessions.Put(ctx, sessionExpiresAtKey, time.Now().Add(time.Hour))
				case "malformed":
					service.Sessions.Put(ctx, "auth.binding", 42)
				case "unknown-version":
					service.Sessions.Put(ctx, "auth.binding", "v999:unsupported")
				case "principal-issuer":
					service.Sessions.Put(ctx, sessionIssuerKey, "https://other-issuer.example")
				}
				if _, _, err := service.Sessions.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				principal, found, err := service.AuthenticatedPrincipal(ctx)
				if change == "unchanged" {
					if err != nil || !found || principal.Subject == "" {
						t.Fatalf("same boundary: found=%t error=%v", found, err)
					}
					// A refresh must retain the boundary for subsequent fresh reuse.
					fresh := mustLoadSession(t, service.Sessions, token)
					if _, found, err := service.AuthenticatedPrincipal(fresh); err != nil || !found {
						t.Fatalf("reuse: found=%t error=%v", found, err)
					}
					return
				}
				if !errors.Is(err, ErrNotAuthenticated) || found || principal.Subject != "" || len(principal.Groups) != 0 {
					t.Fatalf("incompatible boundary: found=%t error=%v; want no principal", found, err)
				}
				if calls != 0 {
					t.Fatal("incompatible session reached provider refresh")
				}
				fresh := mustLoadSession(t, service.Sessions, token)
				if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || found {
					t.Fatalf("incompatible session not destroyed: found=%t error=%v", found, err)
				}
			})
		}
	}
}

func TestAuthenticatedPrincipalValidatesSerializedReload(t *testing.T) {
	for _, path := range []string{"fresh", "retry", "refresh"} {
		for _, binding := range []string{"v999:unsupported", "previous-version"} {
			t.Run(path+"/"+binding, func(t *testing.T) {
				service, token := newRefreshService(t, func(context.Context, string) (*oauth2.Token, error) {
					t.Fatal("invalid reloaded session reached refresh")
					return nil, nil
				})
				stale := mustLoadSession(t, service.Sessions, token)
				updated := mustLoadSession(t, service.Sessions, token)
				if binding == "previous-version" {
					_, digest, _ := strings.Cut(service.Sessions.GetString(updated, sessionBindingKey), ":")
					binding = "v1:" + digest
				}
				service.Sessions.Put(updated, sessionBindingKey, binding)
				if path == "fresh" {
					service.Sessions.Put(updated, sessionExpiresAtKey, time.Now().Add(time.Hour))
				}
				if path == "retry" {
					service.Sessions.Put(updated, sessionRefreshCheckedKey, time.Now())
				}
				if _, _, err := service.Sessions.Commit(updated); err != nil {
					t.Fatal(err)
				}
				principal, found, err := service.AuthenticatedPrincipal(stale)
				if !errors.Is(err, ErrNotAuthenticated) || found || principal.Subject != "" {
					t.Fatalf("reload accepted incompatible principal: found=%t error=%v", found, err)
				}
				fresh := mustLoadSession(t, service.Sessions, token)
				if _, found, err := PrincipalFromSession(fresh, service.Sessions); err != nil || found {
					t.Fatalf("reloaded session not destroyed: found=%t error=%v", found, err)
				}
			})
		}
	}
}
