package verify

import (
	"fmt"
)

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
