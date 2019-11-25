package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/alextanhongpin/passwd"
)

type ResetPassword func(context.Context, ResetPasswordRequest) (*ResetPasswordResponse, error)

type (
	ResetPasswordRequest struct {
		Token           string
		Password        string
		ConfirmPassword string
	}
	ResetPasswordResponse struct {
		// Indicator on whether to send or not.
		Success bool
		User    User
	}
)

type resetPasswordRepository interface {
	WithResetPasswordToken(ctx context.Context, token string) (*User, error)
	UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
	UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
}

func NewResetPassword(users resetPasswordRepository) ResetPassword {
	return func(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResponse, error) {
		var (
			token           = strings.TrimSpace(req.Token)
			password        = strings.TrimSpace(req.Password)
			confirmPassword = strings.TrimSpace(req.ConfirmPassword)
		)
		if token == "" {
			return nil, ErrTokenRequired
		}
		if err := validatePassword(password); err != nil {
			return nil, err
		}
		if password != confirmPassword {
			return nil, ErrPasswordDoNotMatch
		}

		user, err := users.WithResetPasswordToken(ctx, token)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		if err != nil {
			return nil, err
		}

		if !user.Recoverable.IsValid() {
			return nil, ErrTokenExpired
		}
		if !user.Recoverable.AllowPasswordChange {
			return nil, ErrPasswordChangeNotAllowed
		}
		// NOTE: Must email be verified first? Not really...user might not
		// verified their account for a long time.
		// if user.EmailVerified {
		//         return nil, ErrConfirmationRequired
		// }
		// Password must not be the same as the old passwords.
		match, err := passwd.Compare(password, user.EncryptedPassword)
		if err != nil {
			return nil, err
		}
		if match {
			return nil, ErrPasswordUsed
		}

		encrypted, err := passwd.Encrypt(password)
		if err != nil {
			return nil, err
		}

		var (
			userID    = strings.TrimSpace(user.ID)
			userEmail = strings.TrimSpace(user.Email)
		)
		if userID == "" {
			return nil, ErrUserIDRequired
		}
		if err := validateEmail(userEmail); err != nil {
			return nil, ErrEmailRequired
		}

		success, err := users.UpdatePassword(ctx, userID, encrypted)
		if err != nil {
			return nil, err
		}

		var recoverable Recoverable
		success, err = users.UpdateRecoverable(ctx, userEmail, recoverable)
		if err != nil {
			return nil, err
		}

		// Clear older sessions when changing password.
		return &ResetPasswordResponse{
			Success: success,
			User:    *user,
		}, nil
	}
}

type ResetPasswordRepository struct {
	WithResetPasswordTokenFunc WithResetPasswordToken
	UpdatePasswordFunc         UpdatePassword
	UpdateRecoverableFunc      UpdateRecoverable
}

func (r *ResetPasswordRepository) WithResetPasswordToken(ctx context.Context, token string) (*User, error) {
	return r.WithResetPasswordTokenFunc(ctx, token)
}

func (r *ResetPasswordRepository) UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error) {
	return r.UpdatePasswordFunc(ctx, userID, encryptedPassword)
}

func (r *ResetPasswordRepository) UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error) {
	return r.UpdateRecoverableFunc(ctx, email, recoverable)
}
