package passport_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alextanhongpin/passport"
	"github.com/stretchr/testify/assert"
)

func TestSendConfirmationValidation(t *testing.T) {
	t.Run("when email is not provided", func(t *testing.T) {
		assert := assert.New(t)
		res, err := sendConfirmation(&mockSendConfirmationRepository{}, "   ")
		assert.Nil(res)
		assert.Equal(passport.ErrEmailRequired, err)
	})

	t.Run("when email is invalid", func(t *testing.T) {
		assert := assert.New(t)
		res, err := sendConfirmation(&mockSendConfirmationRepository{}, "john.d   ")
		assert.Nil(res)
		assert.Equal(passport.ErrEmailInvalid, err)
	})
}

func TestSendConfirmationEmailNewEmail(t *testing.T) {
	assert := assert.New(t)
	res, err := sendConfirmation(&mockSendConfirmationRepository{
		withEmailError: sql.ErrNoRows,
	}, "john.doe@mail.com")
	assert.Nil(res)
	assert.Equal(passport.ErrEmailNotFound, err)
}

func TestSendConfirmationEmailAlreadyVerified(t *testing.T) {
	assert := assert.New(t)
	res, err := sendConfirmation(&mockSendConfirmationRepository{
		withEmailResponse: &passport.User{
			Confirmable: passport.Confirmable{
				ConfirmedAt:      time.Now(),
				UnconfirmedEmail: "",
			},
		},
	}, "john.doe@mail.com")
	assert.Nil(res)
	assert.Equal(passport.ErrEmailVerified, err)
}

func TestSendConfirmationEmailSuccess(t *testing.T) {
	assert := assert.New(t)
	res, err := sendConfirmation(&mockSendConfirmationRepository{
		withEmailResponse: &passport.User{
			Confirmable: passport.Confirmable{
				UnconfirmedEmail: "",
			},
		},
		updateConfirmableResponse: true,
	}, "john.doe@mail.com")
	assert.Nil(err)
	assert.True(res.Success)
	assert.True(res.Token != "")
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

func sendConfirmation(repo *mockSendConfirmationRepository, email string) (*passport.SendConfirmationResponse, error) {
	return passport.NewSendConfirmation(repo)(
		context.TODO(),
		passport.SendConfirmationRequest{email},
	)
}
