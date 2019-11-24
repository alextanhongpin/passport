package passport

import (
	"context"
	"strings"

	"github.com/alextanhongpin/passwd"
)

type Register func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)

type (
	RegisterRequest struct {
		Email    string
		Password string
		// ClientIP  string
		// UserAgent string
	}
	RegisterResponse struct {
		User User
	}
)

type registerRepository interface {
	Create(ctx context.Context, email, password string) (*User, error)
}

type RegisterRepository struct {
	create Create
}

func (r *RegisterRepository) Create(ctx context.Context, email, password string) (*User, error) {
	return r.create(ctx, email, password)
}

func NewRegister(users registerRepository) Register {
	return func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
		var (
			email    = strings.TrimSpace(req.Email)
			password = strings.TrimSpace(req.Password)
		)
		if err := validateEmailAndPassword(email, password); err != nil {
			return nil, err
		}

		encrypted, err := passwd.Encrypt(password)
		if err != nil {
			return nil, err
		}

		user, err := users.Create(ctx, email, encrypted)
		if err != nil {
			return nil, err
		}

		return &RegisterResponse{
			User: *user,
		}, nil
	}
}
