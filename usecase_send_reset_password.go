package passport

import (
	"context"
	"database/sql"
	"errors"
)

type SendResetPassword func(ctx context.Context, email Email) (string, error)

func NewSendResetPassword(users sendResetPasswordRepository) SendResetPassword {
	return func(ctx context.Context, email Email) (string, error) {
		if err := email.Validate(); err != nil {
			return "", err
		}
		recoverable := NewRecoverable()
		success, err := users.UpdateRecoverable(ctx, email.Value(), recoverable)
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrEmailNotFound
		}
		if err != nil {
			return "", err
		}

		// Return enough data for us to send the email.
		return recoverable.ResetPasswordToken, nil
	}
}

type sendResetPasswordRepository interface {
	UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
}

type SendResetPasswordRepository struct {
	UpdateRecoverableFunc UpdateRecoverable
}

func (s *SendResetPasswordRepository) UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error) {
	return s.UpdateRecoverableFunc(ctx, email, recoverable)
}
