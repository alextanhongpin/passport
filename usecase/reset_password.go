package usecase

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alextanhongpin/passport"
)

type (
	resetPasswordRepository interface {
		WithResetPasswordToken(ctx context.Context, token string) (*passport.User, error)
		UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
		UpdateRecoverable(ctx context.Context, email string, recoverable passport.Recoverable) (bool, error)
	}

	ResetPasswordOptions struct {
		Repository               resetPasswordRepository
		EncoderComparer          passwordEncoderComparer
		RecoverableTokenValidity time.Duration
	}

	ResetPassword struct {
		options ResetPasswordOptions
	}
)

func (r *ResetPassword) Exec(ctx context.Context, token passport.Token, password, confirmPassword passport.Password) (*passport.User, error) {
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

	cipherText, err := r.options.EncoderComparer.Encode(password.Byte())
	if err != nil {
		return nil, err
	}

	var (
		userID    = user.UserID()
		userEmail = passport.NewEmail(user.Email)
	)
	if err := userID.Validate(); err != nil {
		return nil, err
	}
	if err := userEmail.Validate(); err != nil {
		return nil, err
	}

	// TODO: Wrap in transactions.
	_, err = r.options.Repository.UpdatePassword(ctx, userID.Value(), cipherText)
	if err != nil {
		return nil, err
	}

	var recoverable passport.Recoverable
	_, err = r.options.Repository.UpdateRecoverable(ctx, userEmail.Value(), recoverable)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *ResetPassword) validate(token passport.Token, password, confirmPassword passport.Password) error {
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

func (r *ResetPassword) findUser(ctx context.Context, token passport.Token) (*passport.User, error) {
	user, err := r.options.Repository.WithResetPasswordToken(ctx, token.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, passport.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *ResetPassword) checkCanResetPassword(recoverable passport.Recoverable) error {
	if err := recoverable.ValidateExpiry(r.options.RecoverableTokenValidity); err != nil {
		return err
	}
	if !recoverable.AllowPasswordChange {
		return passport.ErrPasswordChangeNotAllowed
	}

	return nil
}

func (r *ResetPassword) checkPasswordNotReused(cipherText, plainText passport.Password) error {
	if err := r.options.EncoderComparer.Compare(
		cipherText.Byte(),
		plainText.Byte(),
	); err == nil {
		return passport.ErrPasswordUsed
	}

	return nil
}

func NewResetPassword(options ResetPasswordOptions) *ResetPassword {
	return &ResetPassword{options}
}
