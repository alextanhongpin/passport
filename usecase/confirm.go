package usecase

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alextanhongpin/passport"
)

type (
	confirmRepository interface {
		WithConfirmationToken(ctx context.Context, token string) (*passport.User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error)
	}

	ConfirmOptions struct {
		Repository                confirmRepository
		ConfirmationTokenValidity time.Duration
	}

	Confirm struct {
		options ConfirmOptions
	}
)

func (c *Confirm) Exec(ctx context.Context, token passport.Token) error {
	if err := token.Validate(); err != nil {
		return err
	}

	user, err := c.findUser(ctx, token)
	if err != nil {
		return err
	}

	if err := c.checkEmailPresent(user); err != nil {
		return err
	}

	if err := c.checkCanConfirm(user.Confirmable); err != nil {
		return err
	}

	if err := c.checkConfirmationTokenValid(user.Confirmable); err != nil {
		return err
	}

	var confirmable passport.Confirmable
	_, err = c.options.Repository.UpdateConfirmable(ctx, user.Email, confirmable)
	return err
}

func (c *Confirm) findUser(ctx context.Context, token passport.Token) (*passport.User, error) {
	user, err := c.options.Repository.WithConfirmationToken(ctx, token.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, passport.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *Confirm) checkEmailPresent(user *passport.User) error {
	email := passport.NewEmail(user.Email)
	return email.Validate()
}

func (c *Confirm) checkCanConfirm(confirmable passport.Confirmable) error {
	return confirmable.ValidateConfirmed()
}

func (c *Confirm) checkConfirmationTokenValid(confirmable passport.Confirmable) error {
	return confirmable.ValidateExpiry(c.options.ConfirmationTokenValidity)
}

func NewConfirm(options ConfirmOptions) *Confirm {
	return &Confirm{options}
}
