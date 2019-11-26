package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type Confirm func(context.Context, ConfirmRequest) (*ConfirmResponse, error)

type (
	ConfirmRequest struct {
		Token string `json:"token"`
	}
	ConfirmResponse struct {
		Success bool `json:"success"`
	}
)

type confirmRepository interface {
	WithConfirmationToken(ctx context.Context, token string) (*User, error)
	UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
}

func NewConfirm(users confirmRepository) Confirm {
	return func(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
		token := strings.TrimSpace(req.Token)
		if token == "" {
			return nil, ErrTokenRequired
		}
		user, err := users.WithConfirmationToken(ctx, token)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		if err != nil {
			return nil, err
		}

		var (
			email = strings.TrimSpace(user.Email)
		)

		if err := validateEmail(email); err != nil {
			return nil, err
		}

		if user.Confirmable.IsVerified() {
			return nil, ErrEmailVerified
		}

		if !user.Confirmable.IsValid() {
			return nil, ErrTokenExpired
		}

		// Reset confirmable.
		var confirmable Confirmable
		success, err := users.UpdateConfirmable(ctx, email, confirmable)
		if err != nil {
			return nil, err
		}

		return &ConfirmResponse{
			Success: success,
		}, nil
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
