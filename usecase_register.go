package passport

import (
	"context"
)

type (
	registerRepository interface {
		Create(ctx context.Context, email, password string) (*User, error)
	}

	register interface {
		Exec(ctx context.Context, cred Credential) (*User, error)
	}

	Register struct {
		users registerRepository
	}
)

func (r *Register) Exec(ctx context.Context, cred Credential) (*User, error) {
	if err := r.validate(cred); err != nil {
		return nil, err
	}

	pwd, err := r.encryptPassword(cred.Password)
	if err != nil {
		return nil, err
	}

	var (
		email    = cred.Email.Value()
		password = pwd.Value()
	)
	user, err := r.users.Create(ctx, email, password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Register) validate(cred Credential) error {
	return cred.Validate()
}

func (r *Register) encryptPassword(password Password) (SecurePassword, error) {
	return password.Encrypt()
}

// NewRegister returns a new Register service.
func NewRegister(repository registerRepository) *Register {
	return &Register{repository}
}
