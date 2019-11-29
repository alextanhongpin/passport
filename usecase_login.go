package passport

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/alextanhongpin/passwd"
)

type Login func(context.Context, LoginRequest) (*LoginResponse, error)

type loginRepository interface {
	WithEmail(ctx context.Context, email string) (*User, error)
}

type (
	LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	LoginResponse struct {
		User User `json:"user"`
	}
)

type LoginRepository struct {
	WithEmailFunc WithEmail
}

func (l *LoginRepository) WithEmail(ctx context.Context, email string) (*User, error) {
	return l.WithEmailFunc(ctx, email)
}

func NewLogin(users loginRepository) Login {
	return func(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
		var (
			email    = strings.TrimSpace(req.Email)
			password = strings.TrimSpace(req.Password)
		)
		if err := validateEmailAndPassword(email, password); err != nil {
			return nil, err
		}

		user, err := users.WithEmail(ctx, email)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEmailNotFound
		}
		if err != nil {
			return nil, err
		}

		match, err := passwd.Compare(password, user.EncryptedPassword)
		if err != nil {
			return nil, err
		}
		if !match {
			return nil, ErrEmailOrPasswordInvalid
		}

		if user.IsConfirmationRequired() {
			return nil, ErrConfirmationRequired
		}

		return &LoginResponse{
			User: *user,
		}, err
	}
}
