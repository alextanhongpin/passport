package passport_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alextanhongpin/passport"

	"github.com/stretchr/testify/assert"
)

func TestRequestResetPasswordValidation(t *testing.T) {
	tests := []struct {
		name  string
		email string
		err   error
	}{
		{"when email is empty", "", passport.ErrEmailRequired},
		{"when email is not provided", "   ", passport.ErrEmailRequired},
		{"when email is invalid", "john", passport.ErrEmailInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			token, err := requestResetPassword(&mockRequestResetPasswordRepository{}, tt.email)
			assert.Equal("", token)
			assert.Equal(tt.err, err)
		})
	}
}

func TestRequestResetPasswordNewEmail(t *testing.T) {
	assert := assert.New(t)
	token, err := requestResetPassword(&mockRequestResetPasswordRepository{
		updateRecoverableError: sql.ErrNoRows,
	}, "john.doe@mail.com")
	assert.Equal("", token)
	assert.Equal(passport.ErrUserNotFound, err)
}

func TestRequestResetPasswordSuccess(t *testing.T) {
	assert := assert.New(t)
	token, err := requestResetPassword(&mockRequestResetPasswordRepository{
		updateRecoverableResponse: true,
	}, "john.doe@mail.com")
	assert.Nil(err)
	assert.True(token != "")
}

type mockRequestResetPasswordRepository struct {
	updateRecoverableResponse bool
	updateRecoverableError    error
}

func (m *mockRequestResetPasswordRepository) UpdateRecoverable(ctx context.Context, email string, recoverable passport.Recoverable) (bool, error) {
	return m.updateRecoverableResponse, m.updateRecoverableError
}

func requestResetPasswordOptions(r *mockRequestResetPasswordRepository) passport.RequestResetPasswordOptions {
	return passport.RequestResetPasswordOptions{
		Repository:     r,
		TokenGenerator: passport.NewTokenGenerator(),
	}
}

func requestResetPassword(r *mockRequestResetPasswordRepository, email string) (string, error) {
	return passport.NewRequestResetPassword(requestResetPasswordOptions(r)).Exec(
		context.TODO(),
		passport.NewEmail(email),
	)
}
