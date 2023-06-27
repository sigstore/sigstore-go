package verifier

import (
	"errors"
	"fmt"
)

var ErrValidation = errors.New("validation error")
var ErrIncorrectMediaType = fmt.Errorf("%w: unsupported media type", ErrValidation)
var ErrMissingVerificationMaterial = fmt.Errorf("%w: missing verification material", ErrValidation)
var ErrUnimplemented = errors.New("unimplemented")

type ErrVerification struct {
	err error
}

func NewVerificationError(e error) ErrVerification {
	return ErrVerification{e}
}

func (e ErrVerification) Unwrap() error {
	return e.err
}

func (e ErrVerification) String() string {
	return fmt.Sprintf("verification error: %s", e.err.Error())
}

func (e ErrVerification) Error() string {
	return e.String()
}

func ErrValidationError(err error) error {
	return fmt.Errorf("%w: %w", ErrValidation, err)
}
