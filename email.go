package passport

import (
	"errors"
	"strings"
)

// TODO: Separate model errors and application errors, and place errors in
// models. Have a method Valid() that returns bool, and another method
// Validate() that returns error.
var (
	ErrEmailExists            = errors.New("email exists")
	ErrEmailInvalid           = errors.New("email invalid")
	ErrEmailOrPasswordInvalid = errors.New("email or password is invalid")
	ErrEmailRequired          = errors.New("email required")
	ErrEmailVerified          = errors.New("email verified")
)

type Email string

func (e Email) Valid() bool {
	return emailRegex.MatchString(e.Value())
}

func (e Email) Validate() error {
	if e.Value() == "" {
		return ErrEmailRequired
	}
	if !e.Valid() {
		return ErrEmailInvalid
	}
	return nil
}

func (e Email) String() string {
	return string(e)
}

func (e Email) Value() string {
	return string(e)
}

func NewEmail(email string) Email {
	return Email(strings.TrimSpace(email))
}
