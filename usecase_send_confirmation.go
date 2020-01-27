package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	sendConfirmation interface {
		Exec(ctx context.Context, email Email) (string, error)
	}

	sendConfirmationRepository interface {
		WithEmail(ctx context.Context, email string) (*User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
	}
	SendConfirmation struct {
		users sendConfirmationRepository
	}
)

func (s *SendConfirmation) Exec(ctx context.Context, email Email) (string, error) {
	if err := email.Validate(); err != nil {
		return "", err
	}

	user, err := s.findUser(ctx, email)
	if err != nil {
		return "", err
	}

	if verified := user.Confirmable.Verified(); verified {
		return "", ErrEmailVerified
	}

	confirmable := NewConfirmable(email.Value())
	_, err = s.users.UpdateConfirmable(ctx, email.Value(), confirmable)
	if err != nil {
		return "", err
	}

	// Return the confirmable in order to send the email.
	return confirmable.ConfirmationToken, nil
}

func (s *SendConfirmation) findUser(ctx context.Context, email Email) (*User, error) {
	user, err := s.users.WithEmail(ctx, email.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
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

func NewSendConfirmation(repository sendConfirmationRepository) *SendConfirmation {
	return &SendConfirmation{repository}
}
