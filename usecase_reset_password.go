package passport

import (
	"context"
	"database/sql"
	"errors"
)

type ResetPassword func(ctx context.Context, token Token, password, confirmPassword Password) (*User, error)

type resetPasswordRepository interface {
	WithResetPasswordToken(ctx context.Context, token string) (*User, error)
	UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
	UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
}

func NewResetPassword(users resetPasswordRepository) ResetPassword {
	validate := func(token Token, password, confirmPassword Password) error {
		if err := token.Validate(); err != nil {
			return err
		}
		if err := password.ValidateEqual(confirmPassword); err != nil {
			return err
		}
		if err := password.Validate(); err != nil {
			return err
		}
		return nil
	}

	findUser := func(ctx context.Context, token Token) (*User, error) {
		user, err := users.WithResetPasswordToken(ctx, token.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	checkCanResetPassword := func(recoverable Recoverable) error {
		if !recoverable.Valid() {
			return ErrTokenExpired
		}
		if !recoverable.AllowPasswordChange {
			return ErrPasswordChangeNotAllowed
		}
		return nil
	}

	checkPasswordNotReused := func(encrypted SecurePassword, password Password) error {
		if match := encrypted.Compare(password); match {
			return ErrPasswordUsed
		}
		return nil
	}

	return func(ctx context.Context, token Token, password, confirmPassword Password) (*User, error) {
		if err := validate(token, password, confirmPassword); err != nil {
			return nil, err
		}
		user, err := findUser(ctx, token)
		if err != nil {
			return nil, err
		}

		if err := checkCanResetPassword(user.Recoverable); err != nil {
			return nil, err
		}
		if err := checkPasswordNotReused(
			SecurePassword(user.EncryptedPassword),
			password,
		); err != nil {
			return nil, err
		}

		securePwd, err := password.Encrypt()
		if err != nil {
			return nil, err
		}

		var (
			userID    = UserIDFactory().FromString(user.ID)
			userEmail = NewEmail(user.Email)
		)
		if err := userID.Validate(); err != nil {
			return nil, err
		}
		if err := userEmail.Validate(); err != nil {
			return nil, err
		}

		// TODO: Wrap in transactions.
		_, err = users.UpdatePassword(ctx, userID.Value(), securePwd.Value())
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
