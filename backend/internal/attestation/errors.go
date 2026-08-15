package attestation

import "errors"

var (
	// ErrMalformed identifies syntactically or schema-invalid attestation data.
	// It intentionally carries no parser detail or input data.
	ErrMalformed = errors.New("malformed rotation attestation")

	// ErrInvalidSigningKey indicates invalid local signing-key input.
	ErrInvalidSigningKey = errors.New("invalid attestation signing key")

	// ErrInvalidVerifyOptions indicates invalid local verification configuration.
	ErrInvalidVerifyOptions = errors.New("invalid attestation verification options")

	// errMalformed is the package-internal sentinel used while validating
	// untrusted values. Public callers receive ErrMalformed instead.
	errMalformed = ErrMalformed
)

// VerificationReason is the closed semantic vocabulary returned after a
// syntactically valid attestation has been checked.
type VerificationReason string

const (
	SignatureInvalid     VerificationReason = "signature_invalid"
	UnknownKey           VerificationReason = "unknown_key"
	KeyRevoked           VerificationReason = "key_revoked"
	IssuerMismatch       VerificationReason = "issuer_mismatch"
	UnsupportedVersion   VerificationReason = "unsupported_version"
	InputDigestMismatch  VerificationReason = "input_digest_mismatch"
	OutputDigestMismatch VerificationReason = "output_digest_mismatch"
	BindingMismatch      VerificationReason = "binding_mismatch"

	// Reason-prefixed aliases make the semantic vocabulary discoverable without
	// requiring callers to rely on the short constant names.
	ReasonSignatureInvalid     = SignatureInvalid
	ReasonUnknownKey           = UnknownKey
	ReasonKeyRevoked           = KeyRevoked
	ReasonIssuerMismatch       = IssuerMismatch
	ReasonUnsupportedVersion   = UnsupportedVersion
	ReasonInputDigestMismatch  = InputDigestMismatch
	ReasonOutputDigestMismatch = OutputDigestMismatch
	ReasonBindingMismatch      = BindingMismatch
)

// VerificationError is a safe semantic verification failure. It contains only
// one closed reason and never includes JWS, claims, Vault text, digests, keys,
// or binding values.
type VerificationError struct {
	reason VerificationReason
}

func (e *VerificationError) Error() string {
	if e == nil {
		return "attestation verification failed"
	}
	return "attestation verification failed: " + string(e.reason)
}

// Reason returns the closed semantic reason.
func (e *VerificationError) Reason() VerificationReason {
	if e == nil {
		return ""
	}
	return e.reason
}

func newVerificationError(reason VerificationReason) *VerificationError {
	return &VerificationError{reason: reason}
}

// VerificationReasonOf extracts a semantic reason without exposing any
// implementation or cryptographic-library error.
func VerificationReasonOf(err error) (VerificationReason, bool) {
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr == nil {
		return "", false
	}
	return verificationErr.reason, true
}
