package attestationkeyring

import "errors"

var (
	// ErrInvalidKeyring means the complete keyring document failed schema or
	// key-material validation. It never contains input data or key material.
	ErrInvalidKeyring = errors.New("invalid attestation keyring")

	// ErrKeyringUnavailable means the keyring file could not be read.
	ErrKeyringUnavailable = errors.New("attestation keyring unavailable")

	// ErrKeyringTooLarge means the bounded keyring input limit was exceeded.
	ErrKeyringTooLarge = errors.New("attestation keyring exceeds size limit")

	// ErrIssuerMismatch means a resolver request used a different issuer than
	// the locally configured canonical issuer.
	ErrIssuerMismatch = errors.New("attestation issuer mismatch")

	// ErrUnknownKey means the requested key ID is not in the local snapshot.
	ErrUnknownKey = errors.New("attestation key not found")

	// ErrNotReady means no valid immutable snapshot is available.
	ErrNotReady = errors.New("attestation keyring is not ready")

	// ErrClosed means the reload manager has been closed.
	ErrClosed = errors.New("attestation keyring is closed")
)
