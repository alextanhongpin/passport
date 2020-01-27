package passport

import (
	"context"
	"database/sql"
	"errors"
)

type Confirm func(ctx context.Context, token Token) error

type confirmRepository interface {
	WithConfirmationToken(ctx context.Context, token string) (*User, error)
	UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
}

func NewConfirm(users confirmRepository) Confirm {
	findUser := func(ctx context.Context, token Token) (*User, error) {
		user, err := users.WithConfirmationToken(ctx, token.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	return func(ctx context.Context, token Token) error {
		if err := token.Validate(); err != nil {
			return ErrTokenRequired
		}

		user, err := findUser(ctx, token)
		if err != nil {
			return err
		}

		email := NewEmail(user.Email)
		if err := email.Validate(); err != nil {
			return err
		}

		if user.Confirmable.Verified() {
			return ErrEmailVerified
		}

		if err := user.Confirmable.ValidateExpiry(); err != nil {
			return err
		}

		// Reset confirmable.
		var confirmable Confirmable
		_, err = users.UpdateConfirmable(ctx, email.Value(), confirmable)
		return err
	}
}

type ConfirmRepository struct {
	WithConfirmationTokenFunc WithConfirmationToken
	UpdateConfirmableFunc     UpdateConfirmable
}

func (c *ConfirmRepository) WithConfirmationToken(ctx context.Context, token string) (*User, error) {
	return c.WithConfirmationTokenFunc(ctx, token)
}

func (c *ConfirmRepository) UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error) {
	return c.UpdateConfirmableFunc(ctx, email, confirmable)
}
