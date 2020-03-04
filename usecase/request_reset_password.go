package usecase

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alextanhongpin/passport"
)

type (
	requestResetPasswordRepository interface {
		UpdateRecoverable(ctx context.Context, email string, recoverable passport.Recoverable) (bool, error)
	}

	RequestResetPasswordOptions struct {
		Repository     requestResetPasswordRepository
		TokenGenerator tokenGenerator
	}

	RequestResetPassword struct {
		options RequestResetPasswordOptions
	}
)

func (r *RequestResetPassword) Exec(ctx context.Context, email passport.Email) (string, error) {
	if err := email.Validate(); err != nil {
		return "", err
	}

	token, err := r.options.TokenGenerator.Generate()
	if err != nil {
		return "", nil
	}

	recoverable := passport.NewRecoverable(token)
	_, err = r.options.Repository.UpdateRecoverable(ctx, email.Value(), recoverable)
	if errors.Is(err, sql.ErrNoRows) {
		return "", passport.ErrUserNotFound
	}
	if err != nil {
		return "", err
	}

	return recoverable.ResetPasswordToken, nil
}

func NewRequestResetPassword(opts RequestResetPasswordOptions) *RequestResetPassword {
	return &RequestResetPassword{opts}
}
