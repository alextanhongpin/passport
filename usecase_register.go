package passport

import (
	"context"
)

type Register func(ctx context.Context, cred Credential) (*User, error)

type registerRepository interface {
	Create(ctx context.Context, email, password string) (*User, error)
}

func NewRegister(users registerRepository) Register {
	return func(ctx context.Context, cred Credential) (*User, error) {
		if err := cred.Validate(); err != nil {
			return nil, err
			// NOTE: Do not leak error implementation here - do it
			// in the model.
			// return nil, ErrInvalidCredential
		}
		pwd, err := cred.Password.Encrypt()
		if err != nil {
			return nil, err
		}
		user, err := users.Create(ctx, cred.Email.Value(), pwd.Value())
		if err != nil {
			return nil, err
		}
		return user, nil
	}
}

type RegisterRepository struct {
	CreateFunc Create
}

func (r *RegisterRepository) Create(ctx context.Context, email, password string) (*User, error) {
	return r.CreateFunc(ctx, email, password)
}
