package passport

import (
	"context"
	"database/sql"
	"errors"
)

type ChangePassword func(ctx context.Context, currentUserID string, password, confirmPassword Password) error

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
	return func(ctx context.Context, currentUserID string, password, confirmPassword Password) error {
		if !(password.Valid() && confirmPassword.Valid()) {
			return ErrPasswordTooShort
		}
		if equal := password.Equal(confirmPassword); !equal {
			return ErrPasswordDoNotMatch
		}
		if currentUserID == "" {
			return ErrUserIDRequired
		}

		user, err := users.Find(ctx, currentUserID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		if err != nil {
			return err
		}

		if match := SecurePassword(user.EncryptedPassword).Compare(password); match {
			return ErrPasswordUsed
		}
		securePwd, err := password.Encrypt()
		if err != nil {
			return err
		}
		_, err = users.UpdatePassword(ctx, currentUserID, securePwd.Value())
		return err
	}
}
