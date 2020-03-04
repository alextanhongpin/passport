package usecase_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passport/usecase"

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
			res, err := login(
				&mockLoginRepository{},
				tt.email,
				tt.password)
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
		password = passport.NewPassword("12345678")
	)
	a2 := passport.NewArgon2Password()
	encrypted, err := a2.Encode(password.Byte())
	assert.Nil(err)

	repo := &mockLoginRepository{
		User: &passport.User{
			Email:             email,
			EncryptedPassword: passport.NewPassword(encrypted),
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

func loginOptions(r *mockLoginRepository) usecase.LoginOptions {
	return usecase.LoginOptions{
		Repository: r,
		Comparer:   passport.NewArgon2Password(),
	}
}

func login(
	r *mockLoginRepository,
	email, password string,
) (*passport.User, error) {
	svc := usecase.NewLogin(loginOptions(r))
	return svc.Exec(
		context.TODO(),
		passport.NewCredential(email, password),
	)
}
