package passport

import (
	"context"
	"database/sql"
	"errors"
)

type ChangeEmail func(ctx context.Context, currentUserID string, email Email) (string, error)

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
	return func(ctx context.Context, currentUserID string, email Email) (string, error) {
		if ok := email.Valid(); !ok {
			return "", ErrEmailInvalid
		}
		if currentUserID == "" {
			return "", ErrUserIDRequired
		}

		exists, err := users.HasEmail(ctx, email.Value())
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		if exists {
			return "", ErrEmailExists
		}

		user, err := users.Find(ctx, currentUserID)
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrUserNotFound
		}
		if err != nil {
			return "", err
		}
		currEmail := NewEmail(user.Email)
		if ok := currEmail.Valid(); !ok {
			return "", ErrEmailInvalid
		}

		var confirmable = NewConfirmable(email.Value())
		if _, err = users.UpdateConfirmable(ctx, currEmail.Value(), confirmable); err != nil {
			return "", err
		}

		// Return the confirmable in order to send the email.
		return confirmable.ConfirmationToken, nil
	}
}
