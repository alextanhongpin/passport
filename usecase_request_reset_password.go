package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	requestResetPasswordRepository interface {
		UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
	}

	RequestResetPasswordOptions struct {
		Repository     requestResetPasswordRepository
		TokenGenerator tokenGenerator
	}

	RequestResetPassword struct {
		options RequestResetPasswordOptions
	}
)

func (r *RequestResetPassword) Exec(ctx context.Context, email Email) (string, error) {
	if err := email.Validate(); err != nil {
		return "", err
	}

	token, err := r.options.TokenGenerator.Generate()
	if err != nil {
		return "", nil
	}
	recoverable := NewRecoverable(token)
	_, err = r.options.Repository.UpdateRecoverable(ctx, email.Value(), recoverable)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", err
	}

	// TODO: Allow token to be customized.
	// Return enough data for us to send the email.
	return recoverable.ResetPasswordToken, nil
}

func NewRequestResetPassword(opts RequestResetPasswordOptions) *RequestResetPassword {
	return &RequestResetPassword{opts}
}
