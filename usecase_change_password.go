package passport

import (
	"context"
	"database/sql"
	"errors"
)

type ChangePassword func(ctx context.Context, currentUserID UserID, password, confirmPassword Password) error

type changePasswordRepository interface {
	Find(ctx context.Context, id string) (*User, error)
	UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
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

func NewChangePassword(users changePasswordRepository) ChangePassword {
	validate := func(userID UserID, password, confirmPassword Password) error {
		if err := password.ValidateEqual(confirmPassword); err != nil {
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

	findUser := func(ctx context.Context, userID UserID) (*User, error) {
		user, err := users.Find(ctx, userID.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	checkPasswordNotUsed := func(encrypted SecurePassword, plainText Password) error {
		if match := encrypted.Compare(plainText); match {
			return ErrPasswordUsed
		}
		return nil
	}

	return func(ctx context.Context, currentUserID UserID, password, confirmPassword Password) error {
		if err := validate(currentUserID, password, confirmPassword); err != nil {
			return err
		}

		user, err := findUser(ctx, currentUserID)
		if err != nil {
			return err
		}

		if err := checkPasswordNotUsed(SecurePassword(user.EncryptedPassword), password); err != nil {
			return err
		}

		securePwd, err := password.Encrypt()
		if err != nil {
			return err
		}
		_, err = users.UpdatePassword(ctx, currentUserID.Value(), securePwd.Value())
		return err
	}
}
