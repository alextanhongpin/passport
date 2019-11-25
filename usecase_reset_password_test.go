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

func TestResetPasswordValidation(t *testing.T) {
	tests := []struct {
		name            string
		token           string
		password        string
		confirmPassword string
		err             error
	}{
		{"when token is empty", "", "123456", "123456", passport.ErrTokenRequired},
		{"when password is empty", "xyz", "", "123456", passport.ErrPasswordRequired},
		{"when password is too short", "xyz", "1", "123456", passport.ErrPasswordTooShort},
		{"when password do not match", "xyz", "123456", "654321", passport.ErrPasswordDoNotMatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			res, err := resetPassword(&mockResetPasswordRepository{}, tt.token, tt.password, tt.confirmPassword)
			assert.Nil(res)
			assert.Equal(tt.err, err)
		})
	}
}

func TestResetPasswordNewEmail(t *testing.T) {
	var (
		token           = "xyz"
		password        = "123456"
		confirmPassword = "123456"
	)
	assert := assert.New(t)
	res, err := resetPassword(&mockResetPasswordRepository{
		withResetPasswordError: sql.ErrNoRows,
	}, token, password, confirmPassword)
	assert.Nil(res)
	assert.Equal(passport.ErrTokenNotFound, err)
}

func TestResetPasswordTokenExpired(t *testing.T) {
	var (
		token           = "xyz"
		password        = "123456"
		confirmPassword = "123456"
	)
	assert := assert.New(t)
	res, err := resetPassword(&mockResetPasswordRepository{
		withResetPasswordTokenResponse: &passport.User{
			Recoverable: passport.Recoverable{
				ResetPasswordSentAt: time.Now().Add(-2 * time.Hour),
			},
		},
	}, token, password, confirmPassword)
	assert.Nil(res)
	assert.Equal(passport.ErrTokenExpired, err)
}

func TestResetPasswordNotAllowed(t *testing.T) {
	var (
		token           = "xyz"
		password        = "123456"
		confirmPassword = "123456"
	)
	assert := assert.New(t)
	res, err := resetPassword(&mockResetPasswordRepository{
		withResetPasswordTokenResponse: &passport.User{
			Recoverable: passport.Recoverable{
				ResetPasswordSentAt: time.Now(),
				AllowPasswordChange: false,
			},
		},
	}, token, password, confirmPassword)
	assert.Nil(res)
	assert.Equal(passport.ErrPasswordChangeNotAllowed, err)
}

func TestResetPasswordSamePassword(t *testing.T) {
	assert := assert.New(t)
	var (
		token           = "xyz"
		password        = "123456"
		confirmPassword = "123456"
	)
	encrypted, err := passwd.Encrypt(password)
	assert.Nil(err)

	res, err := resetPassword(&mockResetPasswordRepository{
		withResetPasswordTokenResponse: &passport.User{
			EncryptedPassword: encrypted,
			Recoverable: passport.Recoverable{
				ResetPasswordSentAt: time.Now(),
				AllowPasswordChange: true,
			},
		},
	}, token, password, confirmPassword)
	assert.Nil(res)
	assert.Equal(passport.ErrPasswordUsed, err)
}

func TestResetPasswordSuccess(t *testing.T) {
	assert := assert.New(t)
	var (
		token           = "xyz"
		password        = "123456"
		confirmPassword = "123456"
		oldPassword     = "654321"
	)

	encrypted, err := passwd.Encrypt(oldPassword)
	assert.Nil(err)

	res, err := resetPassword(&mockResetPasswordRepository{
		withResetPasswordTokenResponse: &passport.User{
			ID:                "123",
			Email:             "john.doe@mail.com",
			EncryptedPassword: encrypted,
			Recoverable: passport.Recoverable{
				ResetPasswordSentAt: time.Now(),
				AllowPasswordChange: true,
			},
		},
		updatePasswordResponse:    true,
		updateRecoverableResponse: true,
	}, token, password, confirmPassword)
	assert.Nil(err)
	assert.True(res.Success)
	assert.NotNil(res.User)
}

type mockResetPasswordRepository struct {
	withResetPasswordTokenResponse *passport.User
	withResetPasswordError         error
	updatePasswordResponse         bool
	updatePasswordError            error
	updateRecoverableResponse      bool
	updateRecoverableError         error
}

func (m *mockResetPasswordRepository) WithResetPasswordToken(ctx context.Context, token string) (*passport.User, error) {
	return m.withResetPasswordTokenResponse, m.withResetPasswordError
}

func (m *mockResetPasswordRepository) UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error) {
	return m.updatePasswordResponse, m.updatePasswordError
}

func (m *mockResetPasswordRepository) UpdateRecoverable(ctx context.Context, email string, recoverable passport.Recoverable) (bool, error) {
	return m.updateRecoverableResponse, m.updateRecoverableError
}

func resetPassword(repo *mockResetPasswordRepository, token, password, confirmPassword string) (*passport.ResetPasswordResponse, error) {
	return passport.NewResetPassword(repo)(
		context.TODO(),
		passport.ResetPasswordRequest{
			Token:           token,
			Password:        password,
			ConfirmPassword: confirmPassword,
		},
	)
}
