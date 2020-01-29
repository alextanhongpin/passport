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

		{"when email is not provided", "", "12345678", passport.ErrEmailRequired},
		{"when email is not valid", "john.doe", "123456", passport.ErrEmailInvalid},
		{"when password is not provided", "john.doe@mail.com", "", passport.ErrPasswordRequired},
		{"when password is not provided", "john.doe@mail.com", "    ", passport.ErrPasswordTooShort},
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
		password = "12345678"
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

func registerOptions(r *mockRegisterRepository) passport.RegisterOptions {
	return passport.RegisterOptions{
		Repository: r,
		Encoder:    passport.NewArgon2Password(),
	}
}

func register(r *mockRegisterRepository, email, password string) (*passport.User, error) {
	return passport.NewRegister(registerOptions(r)).Exec(
		context.TODO(),
		passport.NewCredential(email, password),
	)
}
