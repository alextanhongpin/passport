package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	RequestResetPasswordOptions struct {
		Repository requestResetPasswordRepository
	}

	RequestResetPassword struct {
		options RequestResetPasswordOptions
	}

	requestResetPasswordRepository interface {
		UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
	}
)

func (r *RequestResetPassword) Exec(ctx context.Context, email Email) (string, error) {
	if err := email.Validate(); err != nil {
		return "", err
	}
	recoverable := NewRecoverable()
	_, err := r.options.Repository.UpdateRecoverable(ctx, email.Value(), recoverable)
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
