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
	ErrPasswordInvalid          = errors.New("password invalid")
)

type Password interface {
	Encrypt() (SecurePassword, error)
	Equal(Password) error
	Validate() error
	Valid() bool
	Value() string
}

func NewPassword(password string) Password {
	return NewPlainTextPassword(password)
}
