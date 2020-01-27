package passport

import (
	"context"
	"database/sql"
	"errors"
)

type Login func(context.Context, Credential) (*User, error)

type loginRepository interface {
	WithEmail(ctx context.Context, email string) (*User, error)
}

type LoginRepository struct {
	WithEmailFunc WithEmail
}

func (l *LoginRepository) WithEmail(ctx context.Context, email string) (*User, error) {
	return l.WithEmailFunc(ctx, email)
}

func NewLogin(users loginRepository) Login {
	return func(ctx context.Context, cred Credential) (*User, error) {
		if err := cred.Validate(); err != nil {
			return nil, err
		}

		user, err := users.WithEmail(ctx, cred.Email.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEmailNotFound
		}
		if err != nil {
			return nil, err
		}

		match := SecurePassword(user.EncryptedPassword).Compare(cred.Password)
		if !match {
			return nil, ErrEmailOrPasswordInvalid
		}

		if user.IsConfirmationRequired() {
			return nil, ErrConfirmationRequired
		}

		return user, nil
	}
}
