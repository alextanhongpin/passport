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

func TestSendConfirmationValidation(t *testing.T) {
	t.Run("when email is not provided", func(t *testing.T) {
		assert := assert.New(t)
		token, err := sendConfirmation(&mockSendConfirmationRepository{}, "   ")
		assert.Equal("", token)
		assert.Equal(passport.ErrEmailRequired, err)
	})

	t.Run("when email is invalid", func(t *testing.T) {
		assert := assert.New(t)
		token, err := sendConfirmation(&mockSendConfirmationRepository{}, "john.d   ")
		assert.Equal("", token)
		assert.Equal(passport.ErrEmailInvalid, err)
	})
}

func TestSendConfirmationEmailNewEmail(t *testing.T) {
	assert := assert.New(t)
	token, err := sendConfirmation(&mockSendConfirmationRepository{
		withEmailError: sql.ErrNoRows,
	}, "john.doe@mail.com")
	assert.Equal("", token)
	assert.Equal(passport.ErrUserNotFound, err)
}

func TestSendConfirmationEmailAlreadyVerified(t *testing.T) {
	assert := assert.New(t)
	token, err := sendConfirmation(&mockSendConfirmationRepository{
		withEmailResponse: &passport.User{
			Confirmable: passport.Confirmable{
				ConfirmedAt:      time.Now(),
				UnconfirmedEmail: "",
			},
		},
	}, "john.doe@mail.com")
	assert.Equal("", token)
	assert.Equal(passport.ErrEmailVerified, err)
}

func TestSendConfirmationEmailSuccess(t *testing.T) {
	assert := assert.New(t)
	token, err := sendConfirmation(&mockSendConfirmationRepository{
		withEmailResponse: &passport.User{
			Confirmable: passport.Confirmable{
				UnconfirmedEmail: "",
			},
		},
		updateConfirmableResponse: true,
	}, "john.doe@mail.com")
	assert.Nil(err)
	assert.True(token != "")
}

type mockSendConfirmationRepository struct {
	withEmailResponse         *passport.User
	withEmailError            error
	updateConfirmableResponse bool
	updateConfirmableError    error
}

func (m *mockSendConfirmationRepository) WithEmail(ctx context.Context, email string) (*passport.User, error) {
	return m.withEmailResponse, m.withEmailError
}

func (m *mockSendConfirmationRepository) UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error) {
	return m.updateConfirmableResponse, m.updateConfirmableError
}

func sendConfirmationOptions(r *mockSendConfirmationRepository) usecase.SendConfirmationOptions {
	return usecase.SendConfirmationOptions{
		Repository:     r,
		TokenGenerator: passport.NewTokenGenerator(),
	}
}

func sendConfirmation(r *mockSendConfirmationRepository, email string) (string, error) {
	return usecase.NewSendConfirmation(sendConfirmationOptions(r)).Exec(
		context.TODO(),
		passport.NewEmail(email),
	)
}
