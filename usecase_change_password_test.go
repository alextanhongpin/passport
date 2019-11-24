package passport_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/alextanhongpin/passwd"

	"github.com/stretchr/testify/assert"
)

func TestChangePasswordValidation(t *testing.T) {
	tests := []struct {
		name            string
		userID          string
		password        string
		confirmPassword string
		err             error
	}{

		{"when user_id is not provided", "", "123456", "123456", passport.ErrUserIDRequired},
		{"when password is not provided", "1", "", "123456", passport.ErrPasswordRequired},
		{"when password is too short", "1", "12345", "12345", passport.ErrPasswordTooShort},
		{"when confirm_password is not provided", "1", "123456", "", passport.ErrPasswordDoNotMatch},
		{"when password do not match", "1", "123456", "654321", passport.ErrPasswordDoNotMatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			res, err := changePassword(&mockChangePasswordRepository{}, tt.userID, tt.password, tt.confirmPassword)
			assert.Nil(res)
			assert.Equal(tt.err, err)
		})
	}
}

func TestChangePasswordNewUser(t *testing.T) {
	assert := assert.New(t)
	var (
		userID          = "user_1"
		password        = "123456"
		confirmPassword = "123456"
	)
	repo := &mockChangePasswordRepository{
		findError: sql.ErrNoRows,
	}
	res, err := changePassword(repo, userID, password, confirmPassword)
	assert.Nil(res)
	assert.Equal(passport.ErrUserNotFound, err)
}

func TestChangePasswordSamePassword(t *testing.T) {
	assert := assert.New(t)
	var (
		userID          = "user_1"
		password        = "123456"
		confirmPassword = "123456"
	)
	encryptedPassword, err := passwd.Encrypt(password)
	assert.Nil(err)

	repo := &mockChangePasswordRepository{
		findResponse: &passport.User{
			EncryptedPassword: encryptedPassword,
		},
	}
	res, err := changePassword(repo, userID, password, confirmPassword)
	assert.Nil(res)
	assert.Equal(passport.ErrPasswordUsed, err)
}

func TestChangePasswordSuccess(t *testing.T) {
	assert := assert.New(t)
	var (
		userID          = "user_1"
		oldPassword     = "123456"
		newPassword     = "654321"
		confirmPassword = "654321"
	)
	encryptedPassword, err := passwd.Encrypt(oldPassword)
	assert.Nil(err)

	repo := &mockChangePasswordRepository{
		findResponse: &passport.User{
			ID:                userID,
			EncryptedPassword: encryptedPassword,
		},
		updatePasswordResponse: true,
	}
	res, err := changePassword(repo, userID, newPassword, confirmPassword)
	assert.Nil(nil)
	assert.True(res.Success)
}

type mockChangePasswordRepository struct {
	findResponse           *passport.User
	findError              error
	updatePasswordResponse bool
	updatePasswordError    error
}

func (m *mockChangePasswordRepository) Find(ctx context.Context, id string) (*passport.User, error) {
	return m.findResponse, m.findError
}

func (m *mockChangePasswordRepository) UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error) {
	return m.updatePasswordResponse, m.updatePasswordError
}

func changePassword(repo *mockChangePasswordRepository, userID, password, confirmPassword string) (*passport.ChangePasswordResponse, error) {
	return passport.NewChangePassword(repo)(
		context.TODO(),
		passport.ChangePasswordRequest{
			ContextUserID:   userID,
			Password:        password,
			ConfirmPassword: confirmPassword,
		},
	)
}
