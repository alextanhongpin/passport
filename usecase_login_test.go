package passport_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passwd"
	"github.com/stretchr/testify/assert"
)

type mockLoginRepository struct {
	User *passport.User
	Err  error
}

func (m *mockLoginRepository) WithEmail(ctx context.Context, email string) (*passport.User, error) {
	return m.User, m.Err
}

func login(repo *mockLoginRepository, email, password string) (*passport.LoginResponse, error) {
	return passport.NewLogin(repo)(
		context.TODO(),
		passport.LoginRequest{email, password},
	)
}

func TestLoginValidation(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name     string
		email    string
		password string
		err      error
	}{
		{"when email is not provided", "", "123456", passport.ErrEmailRequired},
		{"when email is not valid", "john.doe", "123456", passport.ErrEmailInvalid},
		{"when password is not provided", "john.doe@mail.com", "", passport.ErrPasswordRequired},
		{"when password is too short", "john.doe@mail.com", "12345", passport.ErrPasswordTooShort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := login(&mockLoginRepository{}, tt.email, tt.password)
			assert.Nil(res)
			assert.Equal(err, tt.err)
		})
	}
}

func TestLoginNewUser(t *testing.T) {
	assert := assert.New(t)

	repo := &mockLoginRepository{Err: sql.ErrNoRows}
	res, err := login(repo, "john.doe@mail.com", "123456")
	assert.Nil(res)
	assert.Equal(err, passport.ErrEmailNotFound)
}

func TestLoginExistingUser(t *testing.T) {
	assert := assert.New(t)

	var (
		email    = "john.doe@mail.com"
		password = "123456"
	)
	encrypted, err := passwd.Encrypt(password)
	assert.Nil(err)

	repo := &mockLoginRepository{
		User: &passport.User{
			Email:             email,
			EncryptedPassword: encrypted,
		},
		Err: nil,
	}

	t.Run("when password is correct", func(t *testing.T) {
		res, err := login(repo, email, password)
		assert.Nil(err)
		assert.Equal(email, res.User.Email)
		assert.Equal(encrypted, res.User.EncryptedPassword)

	})

	t.Run("when password is incorrect", func(t *testing.T) {
		res, err := login(repo, email, "xyz123")
		assert.Nil(res)
		assert.Equal(err, passport.ErrEmailOrPasswordInvalid)
	})
}
