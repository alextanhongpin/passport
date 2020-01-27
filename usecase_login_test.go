package passport_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passwd"

	"github.com/stretchr/testify/assert"
)

func TestLoginValidation(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name     string
		email    string
		password string
	}{
		{"when email is not provided", "", "123456"},
		{"when email is not valid", "john.doe", "123456"},
		{"when password is not provided", "john.doe@mail.com", ""},
		{"when password is too short", "john.doe@mail.com", "12345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := login(&mockLoginRepository{}, tt.email, tt.password)
			assert.Nil(res)
			assert.Equal(passport.ErrInvalidCredential, err)
		})
	}
}

func TestLoginNewUser(t *testing.T) {
	assert := assert.New(t)
	var (
		email    = "john.doe@mail.com"
		password = "123456"
	)
	repo := &mockLoginRepository{Err: sql.ErrNoRows}
	res, err := login(repo, email, password)
	assert.Nil(res)
	assert.Equal(passport.ErrEmailNotFound, err)
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
			Confirmable: passport.Confirmable{
				ConfirmedAt: time.Now(),
			},
		},
		Err: nil,
	}

	t.Run("when password is correct", func(t *testing.T) {
		user, err := login(repo, email, password)
		assert.Nil(err)
		assert.Equal(email, user.Email)
		assert.Equal(encrypted, user.EncryptedPassword)

	})

	t.Run("when password is incorrect", func(t *testing.T) {
		res, err := login(repo, email, "xyz123")
		assert.Nil(res)
		assert.Equal(passport.ErrEmailOrPasswordInvalid, err)
	})
}

type mockLoginRepository struct {
	User *passport.User
	Err  error
}

func (m *mockLoginRepository) WithEmail(ctx context.Context, email string) (*passport.User, error) {
	return m.User, m.Err
}

func login(repo *mockLoginRepository, email, password string) (*passport.User, error) {
	return passport.NewLogin(repo)(
		context.TODO(),
		passport.NewCredential(email, password),
	)
}
