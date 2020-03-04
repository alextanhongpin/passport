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

func TestConfirmValidation(t *testing.T) {
	assert := assert.New(t)
	err := confirm(&mockConfirmRepository{}, "   ")
	assert.Equal(err, passport.ErrTokenRequired)
}

func TestConfirmNewToken(t *testing.T) {
	assert := assert.New(t)
	var (
		token = "xyz"
	)
	err := confirm(&mockConfirmRepository{
		withConfirmationTokenError: sql.ErrNoRows,
	}, token)
	assert.Equal(err, passport.ErrUserNotFound)
}

func TestConfirmTokenExpired(t *testing.T) {
	assert := assert.New(t)
	var (
		token = "xyz"
	)
	err := confirm(&mockConfirmRepository{
		withConfirmationTokenResponse: &passport.User{
			Email: "john.doe@mail.com",
			Confirmable: passport.Confirmable{
				ConfirmationSentAt: time.Now().Add(-25 * time.Hour),
				ConfirmationToken:  token,
				UnconfirmedEmail:   "john.doe@mail.com",
			},
		},
	}, token)
	assert.Equal(passport.ErrTokenExpired, err)
}

func TestConfirmTokenEmailVerified(t *testing.T) {
	assert := assert.New(t)
	var (
		token = "xyz"
	)
	err := confirm(&mockConfirmRepository{
		withConfirmationTokenResponse: &passport.User{
			Email: "john.doe@mail.com",
			Confirmable: passport.Confirmable{
				ConfirmationSentAt: time.Now().Add(-23 * time.Hour),
				ConfirmedAt:        time.Now(),
				ConfirmationToken:  token,
				UnconfirmedEmail:   "",
			},
		},
	}, token)
	assert.Equal(passport.ErrConfirmed, err)
}

func TestConfirmEmailSuccess(t *testing.T) {
	assert := assert.New(t)
	var (
		token = "xyz"
	)
	err := confirm(&mockConfirmRepository{
		withConfirmationTokenResponse: &passport.User{
			Email: "john.doe@mail.com",
			Confirmable: passport.Confirmable{
				ConfirmationSentAt: time.Now().Add(-23 * time.Hour),
				ConfirmedAt:        time.Now(),
				ConfirmationToken:  token,
				UnconfirmedEmail:   "john.doe@mail.com",
			},
		},
		updateConfirmableResponse: true,
	}, token)
	assert.Nil(err)
}

type mockConfirmRepository struct {
	withConfirmationTokenResponse *passport.User
	withConfirmationTokenError    error
	updateConfirmableResponse     bool
	updateConfirmableError        error
}

func (m *mockConfirmRepository) WithConfirmationToken(ctx context.Context, token string) (*passport.User, error) {
	return m.withConfirmationTokenResponse, m.withConfirmationTokenError
}

func (m *mockConfirmRepository) UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error) {
	return m.updateConfirmableResponse, m.updateConfirmableError
}

func confirmOptions(r *mockConfirmRepository) usecase.ConfirmOptions {
	return usecase.ConfirmOptions{
		Repository:                r,
		ConfirmationTokenValidity: passport.ConfirmationTokenValidity,
	}
}

func confirm(r *mockConfirmRepository, token string) error {
	return usecase.NewConfirm(confirmOptions(r)).Exec(
		context.TODO(),
		passport.NewToken(token),
	)
}
