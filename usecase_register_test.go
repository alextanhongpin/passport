package passport_test

import (
	"context"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/stretchr/testify/assert"
)

func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		password string
		err      error
	}{
		{"when email is not provided", "", "123456", passport.ErrEmailRequired},
		{"when email is not valid", "john.doe", "123456", passport.ErrEmailInvalid},
		{"when password is not provided", "john.doe@mail.com", "", passport.ErrPasswordRequired},
		{"when password is not provided", "john.doe@mail.com", "    ", passport.ErrPasswordRequired},
		{"when password is too short", "john.doe@mail.com", "12345", passport.ErrPasswordTooShort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			res, err := register(&mockRegisterRepository{}, tt.email, tt.password)
			assert.Nil(res)
			assert.Equal(tt.err, err)
		})
	}
}

func TestUserRegisterSuccess(t *testing.T) {
	assert := assert.New(t)
	var (
		email    = "john.doe@mail.com"
		password = "123456"
	)
	res, err := register(&mockRegisterRepository{
		user: &passport.User{},
	}, email, password)
	assert.Nil(err)
	assert.NotNil(res)
}

type mockRegisterRepository struct {
	user *passport.User
	err  error
}

func (m *mockRegisterRepository) Create(ctx context.Context, email, password string) (*passport.User, error) {
	return m.user, m.err
}

func register(repo *mockRegisterRepository, email, password string) (*passport.RegisterResponse, error) {
	return passport.NewRegister(repo)(
		context.TODO(),
		passport.RegisterRequest{email, password},
	)
}
