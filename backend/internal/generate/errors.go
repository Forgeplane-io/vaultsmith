package generate

import "errors"

var (
	// ErrInvalidParameters identifies a caller-controlled policy or identity
	// that is outside the bounded Generate contract. It intentionally carries
	// no submitted value or validation detail.
	ErrInvalidParameters = errors.New("invalid generation parameters")

	// ErrGenerationFailed collapses randomness, key-library, serialization, and
	// consistency failures into one value-free package error.
	ErrGenerationFailed = errors.New("material generation failed")

	// ErrResultSerialization prevents a generator result from being passed to a
	// generic JSON logger or response writer. Transports must map its explicit
	// getters into their own secret-bearing DTOs.
	ErrResultSerialization = errors.New("generation result cannot be serialized directly")
)
