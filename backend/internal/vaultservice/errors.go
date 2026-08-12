package vaultservice

import (
	"context"
	"errors"
)

type Code string

const (
	CodeInvalidRequest         Code = "invalid_request"
	CodeTooLarge               Code = "too_large"
	CodeNotFound               Code = "not_found"
	CodeForbidden              Code = "forbidden"
	CodeNotReady               Code = "not_ready"
	CodeOperationFailed        Code = "operation_failed"
	CodeTemporarilyUnavailable Code = "temporarily_unavailable"
)

// Error contains only a stable classification and safe human text. It never
// wraps submitted values, profile configuration, policy details, or crypto
// errors.
type Error struct {
	code    Code
	message string
	cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (e *Error) Code() Code {
	if e == nil {
		return ""
	}
	return e.code
}

func (e *Error) SafeMessage() string {
	return e.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func HasCode(err error, code Code) bool {
	var domainError *Error
	return errors.As(err, &domainError) && domainError.code == code
}

func errorWithCode(code Code, message string) error {
	return &Error{code: code, message: message}
}

func invalidRequest(message string) error {
	return errorWithCode(CodeInvalidRequest, message)
}

func tooLarge() error {
	return errorWithCode(CodeTooLarge, "value is too large")
}

func notFound() error {
	return errorWithCode(CodeNotFound, "profile was not found")
}

func forbidden() error {
	return errorWithCode(CodeForbidden, "operation is not permitted")
}

func notReady(message string) error {
	return errorWithCode(CodeNotReady, message)
}

func operationFailed() error {
	return errorWithCode(CodeOperationFailed, "vault operation failed")
}

func temporarilyUnavailable(cause ...error) error {
	var safeCause error
	if len(cause) > 0 {
		switch {
		case errors.Is(cause[0], context.Canceled):
			safeCause = context.Canceled
		case errors.Is(cause[0], context.DeadlineExceeded):
			safeCause = context.DeadlineExceeded
		}
	}
	return &Error{code: CodeTemporarilyUnavailable, message: "service is temporarily unavailable", cause: safeCause}
}
