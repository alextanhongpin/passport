package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type ChangeEmail func(context.Context, ChangeEmailRequest) (*ChangeEmailResponse, error)

type (
	ChangeEmailRequest struct {
		ContextUserID string
		Email         string
	}

	ChangeEmailResponse struct {
		Success bool
		Token   string
	}
)

type (
	changeEmailRepository interface {
		HasEmail(ctx context.Context, email string) (bool, error)
		Find(ctx context.Context, id string) (*User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
	}
)

type ChangeEmailRepository struct {
	HasEmailFunc          HasEmail
	FindFunc              Find
	UpdateConfirmableFunc UpdateConfirmable
}

func (c *ChangeEmailRepository) HasEmail(ctx context.Context, email string) (bool, error) {
	return c.HasEmailFunc(ctx, email)
}

func (c *ChangeEmailRepository) UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error) {
	return c.UpdateConfirmableFunc(ctx, email, confirmable)
}

func (c *ChangeEmailRepository) Find(ctx context.Context, id string) (*User, error) {
	return c.FindFunc(ctx, id)
}

func NewChangeEmail(users changeEmailRepository) ChangeEmail {
	return func(ctx context.Context, req ChangeEmailRequest) (*ChangeEmailResponse, error) {
		var (
			email  = strings.TrimSpace(req.Email)
			userID = strings.TrimSpace(req.ContextUserID)
		)

		if err := validateEmail(email); err != nil {
			return nil, err
		}
		if userID == "" {
			return nil, ErrUserIDRequired
		}

		exists, err := users.HasEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrEmailExists
		}

		user, err := users.Find(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}

		var confirmable = NewConfirmable(email)
		success, err := users.UpdateConfirmable(ctx, user.Email, confirmable)
		if err != nil {
			return nil, err
		}

		// Return the confirmable in order to send the email.
		return &ChangeEmailResponse{
			Success: success,
			Token:   confirmable.ConfirmationToken,
		}, nil
	}
}
