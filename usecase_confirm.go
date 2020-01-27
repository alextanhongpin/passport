package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type Confirm func(ctx context.Context, token string) error

type confirmRepository interface {
	WithConfirmationToken(ctx context.Context, token string) (*User, error)
	UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
}

func NewConfirm(users confirmRepository) Confirm {
	return func(ctx context.Context, token string) error {
		token = strings.TrimSpace(token)
		if token == "" {
			return ErrTokenRequired
		}
		user, err := users.WithConfirmationToken(ctx, token)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenNotFound
		}
		if err != nil {
			return err
		}

		email := NewEmail(user.Email)
		if err := email.Validate(); err != nil {
			return err
		}

		if user.Confirmable.IsVerified() {
			return ErrEmailVerified
		}

		if !user.Confirmable.IsValid() {
			return ErrTokenExpired
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
