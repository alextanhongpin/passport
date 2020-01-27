package passport

import (
	"errors"
	"strings"
)

var (
	ErrEmailExists            = errors.New("email exists")
	ErrEmailInvalid           = errors.New("email invalid")
	ErrEmailNotFound          = errors.New("email not found")
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
