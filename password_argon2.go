package passport

import "github.com/alextanhongpin/passwd"

type Argon2Password struct {
	value string
}

func (a *Argon2Password) Value() string {
	return string(a.value)
}

func (a *Argon2Password) Compare(pwd Password) error {
	match, err := passwd.Compare(a.Value(), []byte(pwd.Value()))
	if err != nil {
		return err
	}
	if !match {
		return ErrPasswordInvalid
	}
	return nil
}

func NewArgon2Password(cipher string) *Argon2Password {
	return &Argon2Password{value: cipher}
}

func Argon2Factory(password string) (SecurePassword, error) {
	cipher, err := passwd.Encrypt([]byte(password))
	return &Argon2Password{value: cipher}, err
}
