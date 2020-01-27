package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	resetPassword interface {
		Exec(ctx context.Context, token Token, password, confirmPassword Password) (*User, error)
	}

	resetPasswordRepository interface {
		WithResetPasswordToken(ctx context.Context, token string) (*User, error)
		UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
		UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
	}
)

type ResetPassword struct {
	users resetPasswordRepository
}

func (r *ResetPassword) Exec(ctx context.Context, token Token, password, confirmPassword Password) (*User, error) {
	if err := r.validate(token, password, confirmPassword); err != nil {
		return nil, err
	}
	user, err := r.findUser(ctx, token)
	if err != nil {
		return nil, err
	}

	if err := r.checkCanResetPassword(user.Recoverable); err != nil {
		return nil, err
	}
	if err := r.checkPasswordNotReused(
		user.EncryptedPassword,
		password,
	); err != nil {
		return nil, err
	}

	securePwd, err := password.Encrypt()
	if err != nil {
		return nil, err
	}

	var (
		userID    = user.UserID()
		userEmail = NewEmail(user.Email)
	)
	if err := userID.Validate(); err != nil {
		return nil, err
	}
	if err := userEmail.Validate(); err != nil {
		return nil, err
	}

	// TODO: Wrap in transactions.
	_, err = r.users.UpdatePassword(ctx, userID.Value(), securePwd.Value())
	if err != nil {
		return nil, err
	}

	var recoverable Recoverable
	_, err = r.users.UpdateRecoverable(ctx, userEmail.Value(), recoverable)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *ResetPassword) validate(token Token, password, confirmPassword Password) error {
	if err := token.Validate(); err != nil {
		return err
	}
	if err := password.Equal(confirmPassword); err != nil {
		return err
	}
	if err := password.Validate(); err != nil {
		return err
	}
	return nil
}

func (r *ResetPassword) findUser(ctx context.Context, token Token) (*User, error) {
	user, err := r.users.WithResetPasswordToken(ctx, token.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *ResetPassword) checkCanResetPassword(recoverable Recoverable) error {
	if !recoverable.Valid() {
		return ErrTokenExpired
	}
	if !recoverable.AllowPasswordChange {
		return ErrPasswordChangeNotAllowed
	}
	return nil
}

func (r *ResetPassword) checkPasswordNotReused(encrypted SecurePassword, password Password) error {
	if err := encrypted.Compare(password); err != nil {
		return ErrPasswordUsed
	}
	return nil
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

func NewResetPassword(repository resetPasswordRepository) *ResetPassword {
	return &ResetPassword{repository}
}
