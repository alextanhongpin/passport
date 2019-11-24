package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/alextanhongpin/passwd"
)

type ChangePassword func(context.Context, ChangePasswordRequest) (*ChangePasswordResponse, error)

type (
	ChangePasswordRequest struct {
		ContextUserID   string
		Password        string
		ConfirmPassword string
	}
	ChangePasswordResponse struct {
		Success bool
	}
)

type changePasswordRepository interface {
	Find(ctx context.Context, id string) (*User, error)
	UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
}

type ChangePasswordRepository struct {
	find           Find
	updatePassword UpdatePassword
}

func (c *ChangePasswordRepository) Find(ctx context.Context, id string) (*User, error) {
	return c.find(ctx, id)
}

func (c *ChangePasswordRepository) UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error) {
	return c.updatePassword(ctx, userID, encryptedPassword)
}

func NewChangePassword(users changePasswordRepository) ChangePassword {
	return func(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error) {
		var (
			userID          = strings.TrimSpace(req.ContextUserID)
			password        = strings.TrimSpace(req.Password)
			confirmPassword = strings.TrimSpace(req.ConfirmPassword)
		)
		if password != confirmPassword {
			return nil, ErrPasswordDoNotMatch
		}
		if err := validatePassword(password); err != nil {
			return nil, err
		}

		user, err := users.Find(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}

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

		success, err := users.UpdatePassword(ctx, user.ID, encrypted)
		if err != nil {
			return nil, err
		}
		return &ChangePasswordResponse{
			Success: success,
		}, nil
	}
}
