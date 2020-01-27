package passport

import (
	"context"
	"database/sql"
	"errors"
)

type SendConfirmation func(ctx context.Context, email Email) (string, error)

type sendConfirmationRepository interface {
	WithEmail(ctx context.Context, email string) (*User, error)
	UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
}

func NewSendConfirmation(users sendConfirmationRepository) SendConfirmation {
	return func(ctx context.Context, email Email) (string, error) {
		if err := email.Validate(); err != nil {
			return "", err
		}

		user, err := users.WithEmail(ctx, email.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrEmailNotFound
		}
		if err != nil {
			return "", err
		}

		// Don't resend for users whose email is already confirmed.
		if user.Confirmable.IsVerified() {
			return "", ErrEmailVerified
		}

		confirmable := NewConfirmable(email.Value())
		_, err = users.UpdateConfirmable(ctx, email.Value(), confirmable)
		if err != nil {
			return "", err
		}
		// Return the confirmable in order to send the email.
		return confirmable.ConfirmationToken, nil
	}
}

type SendConfirmationRepository struct {
	WithEmailFunc         WithEmail
	UpdateConfirmableFunc UpdateConfirmable
}

func (s *SendConfirmationRepository) WithEmail(ctx context.Context, email string) (*User, error) {
	return s.WithEmailFunc(ctx, email)
}

func (s *SendConfirmationRepository) UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error) {
	return s.UpdateConfirmableFunc(ctx, email, confirmable)
}
