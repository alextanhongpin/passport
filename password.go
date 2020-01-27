package passport

import (
	"errors"

	"github.com/alextanhongpin/passwd"
)

var (
	ErrPasswordChangeNotAllowed = errors.New("password change not allowed")
	ErrPasswordDoNotMatch       = errors.New("password do not match")
	ErrPasswordRequired         = errors.New("password required")
	ErrPasswordTooShort         = errors.New("password too short")
	ErrPasswordUsed             = errors.New("password cannot be reused")
)

const MinPasswordLength = 6

type Password string

func (p Password) Valid() bool {
	return len(p.Value()) >= MinPasswordLength
}

func (p Password) Validate() error {
	if (p.Value()) == "" {
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

type SecurePassword string

func (s SecurePassword) Compare(password Password) bool {
	match, _ := passwd.Compare(password.Value(), s.Value())
	return match
}

func (s SecurePassword) String() string {
	return string(s)
}
func (s SecurePassword) Value() string {
	return string(s)
}

func NewSecurePassword(password string) (SecurePassword, error) {
	cipher, err := passwd.Encrypt(password)
	return SecurePassword(cipher), err
}
