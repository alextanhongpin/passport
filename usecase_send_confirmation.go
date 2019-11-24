package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type SendConfirmation func(context.Context, SendConfirmationRequest) (*SendConfirmationResponse, error)

type (
	SendConfirmationRequest struct {
		Email string
	}
	SendConfirmationResponse struct {
		// Indicator on whether to send or not.
		Success bool
		Token   string
	}
)

type sendConfirmationRepository interface {
	WithEmail(ctx context.Context, email string) (*User, error)
	UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
}

func NewSendConfirmation(users sendConfirmationRepository) SendConfirmation {
	return func(ctx context.Context, req SendConfirmationRequest) (*SendConfirmationResponse, error) {
		var (
			email = strings.TrimSpace(req.Email)
		)
		if err := validateEmail(email); err != nil {
			return nil, err
		}

		user, err := users.WithEmail(ctx, email)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEmailNotFound
		}
		if err != nil {
			return nil, err
		}

		// Don't resend for users whose email is already confirmed.
		if user.Confirmable.IsVerified() {
			return nil, ErrEmailVerified
		}

		confirmable := NewConfirmable(email)
		success, err := users.UpdateConfirmable(ctx, email, confirmable)
		if err != nil {
			return nil, err
		}
		// Return the confirmable in order to send the email.
		return &SendConfirmationResponse{
			Success: success,
			Token:   confirmable.ConfirmationToken,
		}, nil
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
