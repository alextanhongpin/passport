package passport

import (
	"context"
	"strings"

	"github.com/alextanhongpin/passwd"
)

type Register func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)

type (
	RegisterRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	RegisterResponse struct {
		User User `json:"user"`
	}
)

type registerRepository interface {
	Create(ctx context.Context, email, password string) (*User, error)
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

		if password == encrypted {
			panic("forgetting some validation here?")
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

type RegisterRepository struct {
	CreateFunc Create
}

func (r *RegisterRepository) Create(ctx context.Context, email, password string) (*User, error) {
	return r.CreateFunc(ctx, email, password)
}
