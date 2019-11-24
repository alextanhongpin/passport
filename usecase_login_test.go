package passport_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passwd"
	"github.com/stretchr/testify/assert"
)

// func TestValidation

func TestLoginNewUser(t *testing.T) {
	assert := assert.New(t)

	login := passport.NewLogin(&passport.LoginRepository{
		WithEmailFunc: func(ctx context.Context, email string) (*passport.User, error) {
			return nil, sql.ErrNoRows
		},
	})

	res, err := login(context.TODO(), passport.LoginRequest{
		Email:    "john.doe@mail.com",
		Password: "123456",
	})
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

	login := passport.NewLogin(&passport.LoginRepository{
		WithEmailFunc: func(ctx context.Context, email string) (*passport.User, error) {
			return &passport.User{
				Email:             email,
				EncryptedPassword: encrypted,
			}, nil
		},
	})

	t.Run("when password is correct", func(t *testing.T) {
		res, err := login(context.TODO(), passport.LoginRequest{
			Email:    email,
			Password: password,
		})
		assert.Nil(err)
		assert.Equal(email, res.User.Email)
		assert.Equal(encrypted, res.User.EncryptedPassword)

	})

	t.Run("when password is incorrect", func(t *testing.T) {
		res, err := login(context.TODO(), passport.LoginRequest{
			Email:    email,
			Password: "xyz123",
		})
		assert.Nil(res)
		assert.Equal(err, passport.ErrEmailOrPasswordInvalid)
	})
}
