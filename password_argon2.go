package passport

import "github.com/alextanhongpin/passwd"

type Argon2Password struct {
}

func (a *Argon2Password) Compare(cipherText, plainText []byte) error {
	match, err := passwd.Compare(string(cipherText), plainText)
	if err != nil {
		return err
	}
	if !match {
		return ErrPasswordInvalid
	}
	return nil
}

func (a *Argon2Password) Encode(plainText []byte) (string, error) {
	cipherText, err := passwd.Encrypt(plainText)
	return cipherText, err
}

func NewArgon2Password() *Argon2Password {
	return &Argon2Password{}
}
