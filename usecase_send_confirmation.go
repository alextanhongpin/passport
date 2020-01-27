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

	checkUserAlreadyVerified := func(confirmable Confirmable) error {
		if verified := confirmable.IsVerified(); verified {
			return ErrEmailVerified
		}
		return nil
	}

	return func(ctx context.Context, email Email) (string, error) {
		if err := email.Validate(); err != nil {
			return "", err
		}

		user, err := findUser(ctx, email)
		if err != nil {
			return "", err
		}

		if err := checkUserAlreadyVerified(user.Confirmable); err != nil {
			return "", err
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
