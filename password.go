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

const PasswordMinLen = 8

type (
	passwordEncoder interface {
		Encode(password []byte) (string, error)
	}

	passwordComparer interface {
		Compare(hash, password []byte) error
	}

	passwordEncoderComparer interface {
		passwordEncoder
		passwordComparer
	}
)

type Password struct {
	minLen   int
	password string
}

func (p Password) longEnough() bool {
	return len(p.Value()) >= p.minLen
}

func (p Password) Validate() error {
	if p.Value() == "" {
		return ErrPasswordRequired
	}
	if ok := p.longEnough(); !ok {
		return ErrPasswordTooShort
	}
	return nil
}

func (p Password) Value() string {
	return p.password
}

func (p Password) Byte() []byte {
	return []byte(p.password)
}

func (p Password) Equal(pwd Password) error {
	if p.Value() == pwd.Value() {
		return nil
	}
	return ErrPasswordDoNotMatch
}

type PasswordOption func(p *Password)

func MinLen(len int) PasswordOption {
	return func(pwd *Password) {
		pwd.minLen = len
	}
}

func NewPassword(password string, opts ...PasswordOption) Password {
	pwd := Password{
		password: password,
		minLen:   PasswordMinLen,
	}
	for _, opt := range opts {
		opt(&pwd)
	}
	return pwd
}
