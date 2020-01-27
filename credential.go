package passport

import "errors"

// ErrInvalidCredential indicates the credential is invalid.
var ErrInvalidCredential = errors.New("credential is invalid")

// Credential is the email/password pair to authenticate users.
type Credential struct {
	Email    Email
	Password Password
}

// Valid checks if the email is valid.
func (c Credential) Valid() bool {
	return c.Email.Valid() && c.Password.Valid()
}

// Validate is like Valid, except that it returns error instead of boolean.
func (c Credential) Validate() error {
	if err := c.Email.Validate(); err != nil {
		return err
	}
	if err := c.Password.Validate(); err != nil {
		return err
	}
	return nil
}

// NewCredential returns the email/password pair.
func NewCredential(email, password string) Credential {
	return Credential{
		Email:    NewEmail(email),
		Password: NewPassword(password),
	}
}
