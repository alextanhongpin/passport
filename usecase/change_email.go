package usecase

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alextanhongpin/passport"
)

type (
	changeEmailRepository interface {
		Find(ctx context.Context, id string) (*passport.User, error)
		HasEmail(ctx context.Context, email string) (bool, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable passport.Confirmable) (bool, error)
	}

	ChangeEmailOptions struct {
		Repository     changeEmailRepository
		TokenGenerator tokenGenerator
	}

	ChangeEmail struct {
		options ChangeEmailOptions
	}
)

func (c *ChangeEmail) Exec(ctx context.Context, currentUserID passport.UserID, email passport.Email) (string, error) {
	if err := c.validate(currentUserID, email); err != nil {
		return "", err
	}

	if err := c.checkEmailExists(ctx, email); err != nil {
		return "", err
	}

	user, err := c.findUser(ctx, currentUserID)
	if err != nil {
		return "", err
	}

	oldEmail, err := c.checkEmailPresent(user)
	if err != nil {
		return "", err
	}

	return c.createConfirmationToken(ctx, oldEmail, email)
}

func (c *ChangeEmail) validate(userID passport.UserID, email passport.Email) error {
	if err := email.Validate(); err != nil {
		return err
	}
	if err := userID.Validate(); err != nil {
		return err
	}

	return nil
}

func (c *ChangeEmail) checkEmailExists(ctx context.Context, email passport.Email) error {
	exists, err := c.options.Repository.HasEmail(ctx, email.Value())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if exists {
		return passport.ErrEmailExists
	}

	return nil
}

func (c *ChangeEmail) findUser(ctx context.Context, userID passport.UserID) (*passport.User, error) {
	user, err := c.options.Repository.Find(ctx, userID.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, passport.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *ChangeEmail) checkEmailPresent(user *passport.User) (passport.Email, error) {
	email := passport.NewEmail(user.Email)
	if err := email.Validate(); err != nil {
		return email, err
	}

	return email, nil
}

func (c *ChangeEmail) createConfirmationToken(ctx context.Context, oldEmail, newEmail passport.Email) (string, error) {
	token, err := c.options.TokenGenerator.Generate()
	if err != nil {
		return "", err
	}

	confirmable := passport.NewConfirmable(token, newEmail.Value())
	if _, err = c.options.Repository.UpdateConfirmable(ctx, oldEmail.Value(), confirmable); err != nil {
		return "", err
	}

	return confirmable.ConfirmationToken, nil
}

func NewChangeEmail(opts ChangeEmailOptions) *ChangeEmail {
	return &ChangeEmail{opts}
}
