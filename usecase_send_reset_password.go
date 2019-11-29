package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type SendResetPassword func(context.Context, SendResetPasswordRequest) (*SendResetPasswordResponse, error)

type (
	SendResetPasswordRequest struct {
		Email string `json:"email"`
	}
	SendResetPasswordResponse struct {
		Success bool   `json:"success"`
		Token   string `json:"token"`
	}
)

func NewSendResetPassword(users sendResetPasswordRepository) SendResetPassword {
	return func(ctx context.Context, req SendResetPasswordRequest) (*SendResetPasswordResponse, error) {
		email := strings.TrimSpace(req.Email)
		if err := validateEmail(email); err != nil {
			return nil, err
		}

		recoverable := NewRecoverable()
		success, err := users.UpdateRecoverable(ctx, email, recoverable)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEmailNotFound
		}
		if err != nil {
			return nil, err
		}

		// Return enough data for us to send the email.
		return &SendResetPasswordResponse{
			Success: success,
			Token:   recoverable.ResetPasswordToken,
		}, nil
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
