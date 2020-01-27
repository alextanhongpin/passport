package passport_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alextanhongpin/passport"

	"github.com/stretchr/testify/assert"
)

func TestChangeEmailValidation(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		email  string
		err    error
	}{
		{"when email is not provided", "123456", "", passport.ErrEmailInvalid},
		{"when email is invalid", "123456", "john.doe", passport.ErrEmailInvalid},
		{"when user_id is not provided", "", "john.doe@mail.com", passport.ErrUserIDRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			token, err := changeEmail(&mockChangeEmailRepository{}, tt.userID, tt.email)
			assert.Equal("", token)
			assert.Equal(tt.err, err)
		})
	}
}

func TestChangeEmailExists(t *testing.T) {
	assert := assert.New(t)
	var (
		userID = "123456"
		email  = "john.doe@mail.com"
	)
	repo := &mockChangeEmailRepository{
		hasEmailResponse: true,
	}
	token, err := changeEmail(repo, userID, email)
	assert.Equal("", token)
	assert.Equal(passport.ErrEmailExists, err)
}

func TestChangeEmailNewUser(t *testing.T) {
	assert := assert.New(t)
	var (
		userID = "123456"
		email  = "john.doe@mail.com"
	)
	repo := &mockChangeEmailRepository{
		findError: sql.ErrNoRows,
	}
	token, err := changeEmail(repo, userID, email)
	assert.Equal(passport.ErrUserNotFound, err)
	assert.Equal("", token)
}

func TestChangeEmailSuccess(t *testing.T) {
	assert := assert.New(t)
	var (
		userID = "123456"
		email  = "john.doe@mail.com"
	)
	repo := &mockChangeEmailRepository{
		findResponse: &passport.User{
			Email: email,
			Confirmable: passport.Confirmable{
				ConfirmationToken:  "xyz",
				ConfirmationSentAt: time.Now(),
				UnconfirmedEmail:   "xyz@mail.com",
			},
		},
		updateConfirmableResponse: true,
	}
	token, err := changeEmail(repo, userID, email)
	assert.Nil(err)
	assert.True(token != "")
}

type mockChangeEmailRepository struct {
	hasEmailResponse          bool
	hasEmailError             error
	findResponse              *passport.User
	findError                 error
	updateConfirmableResponse bool
	updateConfirmableError    error
}

func (m *mockChangeEmailRepository) HasEmail(ctx context.Context, email string) (bool, error) {
	return m.hasEmailResponse, m.hasEmailError
}

func (m *mockChangeEmailRepository) Find(ctx context.Context, id string) (*passport.User, error) {
	return m.findResponse, m.findError
}

func (m *mockChangeEmailRepository) UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error) {
	return m.updateConfirmableResponse, m.updateConfirmableError
}

func changeEmail(repo *mockChangeEmailRepository, userID, email string) (string, error) {
	return passport.NewChangeEmail(repo)(
		context.TODO(),
		userID,
		passport.NewEmail(email),
	)
}
