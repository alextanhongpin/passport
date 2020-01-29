package passport

import (
	"context"
)

type (
	registerRepository interface {
		Create(ctx context.Context, email, password string) (*User, error)
	}

	RegisterOptions struct {
		Repository registerRepository
		Encoder    passwordEncoder
	}

	Register struct {
		options RegisterOptions
	}
)

func (r *Register) Exec(ctx context.Context, cred Credential) (*User, error) {
	if err := r.validate(cred); err != nil {
		return nil, err
	}

	cipherText, err := r.encryptPassword(cred.Password.Byte())
	if err != nil {
		return nil, err
	}

	return r.createAccount(ctx, cred.Email.Value(), cipherText)
}

func (r *Register) validate(cred Credential) error {
	return cred.Validate()
}

func (r *Register) encryptPassword(password []byte) (string, error) {
	cipherText, err := r.options.Encoder.Encode(password)
	return cipherText, err
}

func (r *Register) createAccount(ctx context.Context, email, password string) (*User, error) {
	return r.options.Repository.Create(ctx, email, password)
}

// NewRegister returns a new Register service.
func NewRegister(options RegisterOptions) *Register {
	return &Register{options}
}
