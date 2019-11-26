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
		UserID          string
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
	return func(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error) {
		var (
			userID          = strings.TrimSpace(req.UserID)
			password        = strings.TrimSpace(req.Password)
			confirmPassword = strings.TrimSpace(req.ConfirmPassword)
		)
		if err := validatePassword(password); err != nil {
			return nil, err
		}
		if password != confirmPassword {
			return nil, ErrPasswordDoNotMatch
		}
		if userID == "" {
			return nil, ErrUserIDRequired
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

		success, err := users.UpdatePassword(ctx, userID, encrypted)
		if err != nil {
			return nil, err
		}
		return &ChangePasswordResponse{
			Success: success,
		}, nil
	}
}
