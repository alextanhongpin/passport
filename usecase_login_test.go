package passport_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alextanhongpin/passport"

	"github.com/stretchr/testify/assert"
)

func TestLoginValidation(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name     string
		email    string
		password string
		err      error
	}{
		{"when email is not provided", "", "12345678", passport.ErrEmailRequired},
		{"when email is not valid", "john.doe", "12345678", passport.ErrEmailInvalid},
		{"when password is not provided", "john.doe@mail.com", "", passport.ErrPasswordRequired},
		{"when password is too short", "john.doe@mail.com", "12345", passport.ErrPasswordTooShort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := login(&mockLoginRepository{}, tt.email, tt.password)
			assert.Nil(res)
			assert.Equal(tt.err, err)
		})
	}
}

func TestLoginNewUser(t *testing.T) {
	assert := assert.New(t)
	var (
		email    = "john.doe@mail.com"
		password = "12345678"
	)
	repo := &mockLoginRepository{Err: sql.ErrNoRows}
	res, err := login(repo, email, password)
	assert.Nil(res)
	assert.Equal(passport.ErrUserNotFound, err)
}

func TestLoginExistingUser(t *testing.T) {
	assert := assert.New(t)

	var (
		email    = "john.doe@mail.com"
		password = passport.NewPlainTextPassword("12345678")
	)
	encrypted, err := password.Encrypt()
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
		user, err := login(repo, email, password.Value())
		assert.Nil(err)
		assert.Equal(email, user.Email)
		assert.Nil(user.EncryptedPassword.Compare(password))
	})

	t.Run("when password is incorrect", func(t *testing.T) {
		res, err := login(repo, email, "xyz12345")
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
	return passport.NewLogin(repo).Exec(
		context.TODO(),
		passport.NewCredential(email, password),
	)
}
