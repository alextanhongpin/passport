package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	changePassword interface {
		Exec(ctx context.Context, currentUserID UserID, password, confirmPassword Password) error
	}

	changePasswordRepository interface {
		Find(ctx context.Context, id string) (*User, error)
		UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
	}
	ChangePassword struct {
		users changePasswordRepository
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
	securePwd, err := password.Encrypt()
	if err != nil {
		return err
	}
	_, err = c.users.UpdatePassword(ctx, currentUserID.Value(), securePwd.Value())
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
	user, err := c.users.Find(ctx, userID.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (c *ChangePassword) checkPasswordNotUsed(encrypted SecurePassword, plainText Password) error {
	if err := encrypted.Compare(plainText); err != nil {
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

func NewChangePassword(repository changePasswordRepository) *ChangePassword {
	return &ChangePassword{repository}
}
