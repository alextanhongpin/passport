package usecase

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alextanhongpin/passport"
)

type (
	changePasswordRepository interface {
		Find(ctx context.Context, id string) (*passport.User, error)
		UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
	}

	ChangePasswordOptions struct {
		Repository      changePasswordRepository
		EncoderComparer passwordEncoderComparer
	}

	ChangePassword struct {
		options ChangePasswordOptions
	}
)

func (c *ChangePassword) Exec(ctx context.Context, currentUserID passport.UserID, password, confirmPassword passport.Password) error {
	if err := c.validate(currentUserID, password, confirmPassword); err != nil {
		return err
	}

	user, err := c.findUser(ctx, currentUserID)
	if err != nil {
		return err
	}

	if err := c.checkPasswordNotUsed(
		user.EncryptedPassword,
		password,
	); err != nil {
		return err
	}

	cipherText, err := c.options.EncoderComparer.Encode(password.Byte())
	if err != nil {
		return err
	}

	_, err = c.options.Repository.UpdatePassword(ctx, currentUserID.Value(), cipherText)
	return err
}

func (c *ChangePassword) validate(userID passport.UserID, password, confirmPassword passport.Password) error {
	if err := password.Equal(confirmPassword); err != nil {
		return err
	}

	if err := password.Validate(); err != nil {
		return err
	}

	if err := userID.Validate(); err != nil {
		return err
	}

	return nil
}

func (c *ChangePassword) findUser(ctx context.Context, userID passport.UserID) (*passport.User, error) {
	user, err := c.options.Repository.Find(ctx, userID.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, passport.ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *ChangePassword) checkPasswordNotUsed(cipherText, plainText passport.Password) error {
	if err := c.options.EncoderComparer.Compare(
		cipherText.Byte(),
		plainText.Byte(),
	); err == nil {
		return passport.ErrPasswordUsed
	}

	return nil
}

func NewChangePassword(options ChangePasswordOptions) *ChangePassword {
	return &ChangePassword{options}
}
