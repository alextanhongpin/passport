package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	confirm interface {
		Exec(ctx context.Context, token Token) error
	}

	confirmRepository interface {
		WithConfirmationToken(ctx context.Context, token string) (*User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
	}

	Confirm struct {
		users confirmRepository
	}
)

func (c *Confirm) findUser(ctx context.Context, token Token) (*User, error) {
	user, err := c.users.WithConfirmationToken(ctx, token.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (c *Confirm) checkCanConfirm(confirmable Confirmable) error {
	if verified := confirmable.Verified(); verified {
		return ErrEmailVerified
	}

	if err := confirmable.ValidateExpiry(); err != nil {
		return err
	}
	return nil
}

func (c *Confirm) Exec(ctx context.Context, token Token) error {
	if err := token.Validate(); err != nil {
		return ErrTokenRequired
	}

	user, err := c.findUser(ctx, token)
	if err != nil {
		return err
	}

	email := NewEmail(user.Email)
	if err := email.Validate(); err != nil {
		return err
	}

	if err := c.checkCanConfirm(user.Confirmable); err != nil {
		return err
	}

	var confirmable Confirmable
	_, err = c.users.UpdateConfirmable(ctx, email.Value(), confirmable)
	return err
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

func NewConfirm(repository confirmRepository) *Confirm {
	return &Confirm{repository}
}
