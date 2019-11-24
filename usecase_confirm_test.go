package passport_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alextanhongpin/passport"

	"github.com/stretchr/testify/assert"
)

func TestConfirmValidation(t *testing.T) {
	assert := assert.New(t)
	res, err := confirm(&mockConfirmRepository{}, "   ")
	assert.Nil(res)
	assert.Equal(err, passport.ErrTokenRequired)
}

func TestConfirmNewToken(t *testing.T) {
	assert := assert.New(t)
	res, err := confirm(&mockConfirmRepository{
		withConfirmationTokenError: sql.ErrNoRows,
	}, "xyz")
	assert.Nil(res)
	assert.Equal(err, passport.ErrTokenNotFound)
}

func TestConfirmTokenExpired(t *testing.T) {
	assert := assert.New(t)
	res, err := confirm(&mockConfirmRepository{
		withConfirmationTokenResponse: &passport.User{
			Email: "john.doe@mail.com",
			Confirmable: passport.Confirmable{
				ConfirmationSentAt: time.Now().Add(-25 * time.Hour),
				ConfirmationToken:  "",
				UnconfirmedEmail:   "john.doe@mail.com",
			},
		},
	}, "xyz")
	assert.Nil(res)
	assert.Equal(passport.ErrTokenExpired, err)
}

func TestConfirmTokenEmailVerified(t *testing.T) {
	assert := assert.New(t)
	res, err := confirm(&mockConfirmRepository{
		withConfirmationTokenResponse: &passport.User{
			Email: "john.doe@mail.com",
			Confirmable: passport.Confirmable{
				ConfirmationSentAt: time.Now().Add(-23 * time.Hour),
				ConfirmedAt:        time.Now(),
				ConfirmationToken:  "",
				UnconfirmedEmail:   "",
			},
		},
	}, "xyz")
	assert.Nil(res)
	assert.Equal(passport.ErrEmailVerified, err)
}

func TestConfirmEmailSuccess(t *testing.T) {
	assert := assert.New(t)
	res, err := confirm(&mockConfirmRepository{
		withConfirmationTokenResponse: &passport.User{
			Email: "john.doe@mail.com",
			Confirmable: passport.Confirmable{
				ConfirmationSentAt: time.Now().Add(-23 * time.Hour),
				ConfirmedAt:        time.Now(),
				ConfirmationToken:  "",
				UnconfirmedEmail:   "john.doe@mail.com",
			},
		},
		updateConfirmableResponse: true,
	}, "xyz")
	assert.Nil(err)
	assert.True(res.Success)
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

func confirm(repo *mockConfirmRepository, token string) (*passport.ConfirmResponse, error) {
	return passport.NewConfirm(repo)(
		context.TODO(),
		passport.ConfirmRequest{token},
	)
}
