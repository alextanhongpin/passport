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

		{"when user_id is not provided", "", "12345678", "12345678", passport.ErrUserIDRequired},
		{"when password is not provided", "1", "", "12345678", passport.ErrPasswordDoNotMatch},
		{"when password is too short", "1", "12345", "12345", passport.ErrPasswordTooShort},
		{"when confirm_password is not provided", "1", "12345678", "", passport.ErrPasswordDoNotMatch},
		{"when password do not match", "1", "12345678", "87654321", passport.ErrPasswordDoNotMatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := changePassword(&mockChangePasswordRepository{}, tt.userID, tt.password, tt.confirmPassword)
			assert.Equal(tt.err, err)
		})
	}
}

func TestChangePasswordNewUser(t *testing.T) {
	assert := assert.New(t)
	var (
		userID          = "user_1"
		password        = "12345678"
		confirmPassword = "12345678"
	)
	repo := &mockChangePasswordRepository{
		findError: sql.ErrNoRows,
	}
	err := changePassword(repo, userID, password, confirmPassword)
	assert.Equal(passport.ErrUserNotFound, err)
}

func TestChangePasswordSamePassword(t *testing.T) {
	assert := assert.New(t)
	var (
		userID          = "user_1"
		password        = "12345678"
		confirmPassword = "12345678"
	)
	encryptedPassword, err := passwd.Encrypt([]byte(password))
	assert.Nil(err)

	repo := &mockChangePasswordRepository{
		findResponse: &passport.User{
			EncryptedPassword: passport.NewPassword(encryptedPassword),
		},
	}
	err = changePassword(repo, userID, password, confirmPassword)
	assert.Equal(passport.ErrPasswordUsed, err)
}

func TestChangePasswordSuccess(t *testing.T) {
	assert := assert.New(t)
	var (
		userID          = "user_1"
		oldPassword     = "12345678"
		newPassword     = "87654321"
		confirmPassword = "87654321"
	)
	encryptedPassword, err := passwd.Encrypt([]byte(oldPassword))
	assert.Nil(err)

	repo := &mockChangePasswordRepository{
		findResponse: &passport.User{
			ID:                userID,
			EncryptedPassword: passport.NewPassword(encryptedPassword),
		},
		updatePasswordResponse: true,
	}
	err = changePassword(repo, userID, newPassword, confirmPassword)
	assert.Nil(nil)
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

func changePasswordOptions(r *mockChangePasswordRepository) passport.ChangePasswordOptions {
	return passport.ChangePasswordOptions{
		Repository:      r,
		EncoderComparer: passport.NewArgon2Password(),
	}
}

func changePassword(r *mockChangePasswordRepository, userID, password, confirmPassword string) error {
	return passport.NewChangePassword(changePasswordOptions(r)).Exec(
		context.TODO(),
		passport.NewUserID(userID),
		passport.NewPassword(password),
		passport.NewPassword(confirmPassword),
	)
}
