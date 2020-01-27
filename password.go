package passport

import "github.com/alextanhongpin/passwd"

const MinPasswordLength = 6

type Password string

func (p Password) Valid() bool {
	return len(string(p)) >= MinPasswordLength
}

func (p Password) Value() string {
	return string(p)
}

func (p Password) Encrypt() (SecurePassword, error) {
	cipher, err := passwd.Encrypt(string(p))
	return SecurePassword(cipher), err
}

func (p Password) Equal(pwd Password) bool {
	return p.Value() == pwd.Value()
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
