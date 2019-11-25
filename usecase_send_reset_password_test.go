package passport_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/stretchr/testify/assert"
)

func TestSendResetPasswordValidation(t *testing.T) {
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
			res, err := sendResetPassword(&mockSendResetPasswordRepository{}, tt.email)
			assert.Nil(res)
			assert.Equal(tt.err, err)
		})
	}
}

func TestSendResetPasswordNewEmail(t *testing.T) {
	assert := assert.New(t)
	res, err := sendResetPassword(&mockSendResetPasswordRepository{
		updateRecoverableError: sql.ErrNoRows,
	}, "john.doe@mail.com")
	assert.Nil(res)
	assert.Equal(passport.ErrEmailNotFound, err)
}

func TestSendResetPasswordSuccess(t *testing.T) {
	assert := assert.New(t)
	res, err := sendResetPassword(&mockSendResetPasswordRepository{
		updateRecoverableResponse: true,
	}, "john.doe@mail.com")
	assert.Nil(err)
	assert.True(res.Success)
	assert.True(len(res.Token) > 0)
}

type mockSendResetPasswordRepository struct {
	updateRecoverableResponse bool
	updateRecoverableError    error
}

func (m *mockSendResetPasswordRepository) UpdateRecoverable(ctx context.Context, email string, recoverable passport.Recoverable) (bool, error) {
	return m.updateRecoverableResponse, m.updateRecoverableError
}

func sendResetPassword(repo *mockSendResetPasswordRepository, email string) (*passport.SendResetPasswordResponse, error) {
	return passport.NewSendResetPassword(repo)(
		context.TODO(),
		passport.SendResetPasswordRequest{email},
	)
}