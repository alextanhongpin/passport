package usecase

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alextanhongpin/passport"
)

type (
	sendConfirmationRepository interface {
		WithEmail(ctx context.Context, email string) (*passport.User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error)
	}

	SendConfirmationOptions struct {
		Repository     sendConfirmationRepository
		TokenGenerator tokenGenerator
	}

	SendConfirmation struct {
		options SendConfirmationOptions
	}
)

func (s *SendConfirmation) Exec(ctx context.Context, email passport.Email) (string, error) {
	if err := email.Validate(); err != nil {
		return "", err
	}

	user, err := s.findUser(ctx, email)
	if err != nil {
		return "", err
	}

	if err := s.checkNotYetConfirmed(user.Confirmable); err != nil {
		return "", err
	}

	token, err := s.options.TokenGenerator.Generate()
	if err != nil {
		return "", err
	}
	confirmable := passport.NewConfirmable(token, email.Value())
	_, err = s.options.Repository.UpdateConfirmable(ctx, email.Value(), confirmable)
	if err != nil {
		return "", err
	}

	return confirmable.ConfirmationToken, nil
}

func (s *SendConfirmation) findUser(ctx context.Context, email passport.Email) (*passport.User, error) {
	user, err := s.options.Repository.WithEmail(ctx, email.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, passport.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *SendConfirmation) checkNotYetConfirmed(confirmable passport.Confirmable) error {
	if verified := confirmable.Verified(); verified {
		return passport.ErrEmailVerified
	}
	return nil
}

func NewSendConfirmation(options SendConfirmationOptions) *SendConfirmation {
	return &SendConfirmation{options}
}
