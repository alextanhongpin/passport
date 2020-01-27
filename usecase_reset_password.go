package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type ResetPassword func(ctx context.Context, token string, password, confirmPassword Password) (*User, error)

type resetPasswordRepository interface {
	WithResetPasswordToken(ctx context.Context, token string) (*User, error)
	UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
	UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
}

func NewResetPassword(users resetPasswordRepository) ResetPassword {
	return func(ctx context.Context, token string, password, confirmPassword Password) (*User, error) {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, ErrTokenRequired
		}
		if !(password.Valid() && confirmPassword.Valid()) {
			return nil, ErrPasswordTooShort
		}
		if !password.Equal(confirmPassword) {
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
		if match := SecurePassword(user.EncryptedPassword).Compare(password); match {
			return nil, ErrPasswordUsed
		}

		securePwd, err := password.Encrypt()
		if err != nil {
			return nil, err
		}

		var (
			userID    = strings.TrimSpace(user.ID)
			userEmail = NewEmail(user.Email)
		)
		if userID == "" {
			return nil, ErrUserIDRequired
		}
		if ok := userEmail.Valid(); !ok {
			return nil, ErrEmailInvalid
		}

		// TODO: Wrap in transactions.
		_, err = users.UpdatePassword(ctx, userID, securePwd.Value())
		if err != nil {
			return nil, err
		}

		var recoverable Recoverable
		_, err = users.UpdateRecoverable(ctx, userEmail.Value(), recoverable)
		if err != nil {
			return nil, err
		}
		return user, nil
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
