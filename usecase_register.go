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
		Encoder    PasswordEncoder
	}

	Register struct {
		options RegisterOptions
	}
)

func (r *Register) Exec(ctx context.Context, cred Credential) (*User, error) {
	if err := r.validate(cred); err != nil {
		return nil, err
	}

	cipherText, err := r.options.Encoder.Encode(cred.Password.Byte())
	if err != nil {
		return nil, err
	}

	user, err := r.options.Repository.Create(ctx, cred.Email.Value(), cipherText)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Register) validate(cred Credential) error {
	return cred.Validate()
}

// NewRegister returns a new Register service.
func NewRegister(options RegisterOptions) *Register {
	return &Register{options}
}
