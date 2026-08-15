package attestation

import (
	"crypto/ed25519"
	"errors"
)

func resolverForPublic(publicKey ed25519.PublicKey, revoked bool) KeyResolver {
	return resolverFunc(func(issuer, kid string) (KeyResolution, error) {
		if issuer != testIssuer || kid != testKid {
			return KeyResolution{}, errors.New("unknown")
		}
		return KeyResolution{PublicKey: append(ed25519.PublicKey(nil), publicKey...), Revoked: revoked}, nil
	})
}
