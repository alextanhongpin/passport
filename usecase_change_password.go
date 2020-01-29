package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	changePasswordRepository interface {
		Find(ctx context.Context, id string) (*User, error)
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

func (c *ChangePassword) Exec(ctx context.Context, currentUserID UserID, password, confirmPassword Password) error {
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

func (c *ChangePassword) validate(userID UserID, password, confirmPassword Password) error {
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

func (c *ChangePassword) findUser(ctx context.Context, userID UserID) (*User, error) {
	user, err := c.options.Repository.Find(ctx, userID.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (c *ChangePassword) checkPasswordNotUsed(cipherText, plainText Password) error {
	if err := c.options.EncoderComparer.Compare(
		cipherText.Byte(),
		plainText.Byte(),
	); err == nil {
		return ErrPasswordUsed
	}
	return nil
}

type ChangePasswordRepository struct {
	FindFunc           Find
	UpdatePasswordFunc UpdatePassword
}

func (c *ChangePasswordRepository) Find(ctx context.Context, id string) (*User, error) {
	return c.FindFunc(ctx, id)
}

func (c *ChangePasswordRepository) UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error) {
	return c.UpdatePasswordFunc(ctx, userID, encryptedPassword)
}

func NewChangePassword(options ChangePasswordOptions) *ChangePassword {
	return &ChangePassword{options}
}
