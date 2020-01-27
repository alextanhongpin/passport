package passport

import (
	"context"
	"database/sql"
	"errors"
)

type requestResetPassword interface {
	Exec(ctx context.Context, email Email) (string, error)
}

type RequestResetPassword struct {
	users requestResetPasswordRepository
}

func (r *RequestResetPassword) Exec(ctx context.Context, email Email) (string, error) {
	if err := email.Validate(); err != nil {
		return "", err
	}
	recoverable := NewRecoverable()
	_, err := r.users.UpdateRecoverable(ctx, email.Value(), recoverable)
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

type requestResetPasswordRepository interface {
	UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
}

type RequestResetPasswordRepository struct {
	UpdateRecoverableFunc UpdateRecoverable
}

func (r *RequestResetPasswordRepository) UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error) {
	return r.UpdateRecoverableFunc(ctx, email, recoverable)
}

func NewRequestResetPassword(repository requestResetPasswordRepository) *RequestResetPassword {
	return &RequestResetPassword{repository}
}
