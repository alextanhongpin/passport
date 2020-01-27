package passport

import (
	"errors"
)

var ErrInvalidCredential = errors.New("credential is invalid")

type Credential struct {
	Email    Email
	Password Password
}

func (c Credential) Valid() bool {
	return c.Email.Valid() && c.Password.Valid()
}

func NewCredential(email, password string) Credential {
	return Credential{
		Email:    NewEmail(email),
		Password: NewPassword(password),
	}
}
