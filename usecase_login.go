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
	findUser := func(ctx context.Context, email Email) (*User, error) {
		user, err := users.WithEmail(ctx, email.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	checkPasswordMatch := func(encrypted SecurePassword, password Password) error {
		if match := encrypted.Compare(password); !match {
			return ErrEmailOrPasswordInvalid
		}
		return nil
	}

	return func(ctx context.Context, cred Credential) (*User, error) {
		if err := cred.Validate(); err != nil {
			return nil, err
		}
		user, err := findUser(ctx, cred.Email)
		if err != nil {
			return nil, err
		}

		if err := checkPasswordMatch(SecurePassword(user.EncryptedPassword), cred.Password); err != nil {
			return nil, err
		}

		if user.IsConfirmationRequired() {
			return nil, ErrConfirmationRequired
		}

		return user, nil
	}
}
