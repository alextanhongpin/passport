package passport

import (
	"errors"
)

var (
	ErrPasswordChangeNotAllowed = errors.New("password change not allowed")
	ErrPasswordDoNotMatch       = errors.New("password do not match")
	ErrPasswordRequired         = errors.New("password required")
	ErrPasswordTooShort         = errors.New("password too short")
	ErrPasswordUsed             = errors.New("password cannot be reused")
)

const MinPasswordLength = 8

type Password string

func (p Password) Valid() bool {
	return !(len(p.Value()) < MinPasswordLength)
}

func (p Password) Validate() error {
	if p.Value() == "" {
		return ErrPasswordRequired
	}
	if !p.Valid() {
		return ErrPasswordTooShort
	}
	return nil
}

func (p Password) Value() string {
	return string(p)
}

func (p Password) Encrypt() (SecurePassword, error) {
	return NewSecurePassword(p.Value())
}

func (p Password) Equal(pwd Password) bool {
	return p.Value() == pwd.Value()
}

func (p Password) ValidateEqual(pwd Password) error {
	if !p.Equal(pwd) {
		return ErrPasswordDoNotMatch
	}
	return nil
}

func NewPassword(password string) Password {
	return Password(password)
}
