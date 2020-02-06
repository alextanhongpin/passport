package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	changeEmailRepository interface {
		HasEmail(ctx context.Context, email string) (bool, error)
		Find(ctx context.Context, id string) (*User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
	}

	ChangeEmailOptions struct {
		Repository     changeEmailRepository
		TokenGenerator tokenGenerator
	}

	ChangeEmail struct {
		options ChangeEmailOptions
	}
)

func (c *ChangeEmail) Exec(ctx context.Context, currentUserID UserID, email Email) (string, error) {
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

func (c *ChangeEmail) validate(userID UserID, email Email) error {
	if err := email.Validate(); err != nil {
		return err
	}
	if err := userID.Validate(); err != nil {
		return err
	}

	return nil
}

func (c *ChangeEmail) checkEmailExists(ctx context.Context, email Email) error {
	exists, err := c.options.Repository.HasEmail(ctx, email.Value())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if exists {
		return ErrEmailExists
	}

	return nil
}

func (c *ChangeEmail) findUser(ctx context.Context, userID UserID) (*User, error) {
	user, err := c.options.Repository.Find(ctx, userID.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *ChangeEmail) checkEmailPresent(user *User) (Email, error) {
	email := NewEmail(user.Email)
	if err := email.Validate(); err != nil {
		return email, err
	}

	return email, nil
}

func (c *ChangeEmail) createConfirmationToken(ctx context.Context, oldEmail, newEmail Email) (string, error) {
	token, err := c.options.TokenGenerator.Generate()
	if err != nil {
		return "", err
	}

	confirmable := NewConfirmable(token, newEmail.Value())
	if _, err = c.options.Repository.UpdateConfirmable(ctx, oldEmail.Value(), confirmable); err != nil {
		return "", err
	}

	return confirmable.ConfirmationToken, nil
}

func NewChangeEmail(opts ChangeEmailOptions) *ChangeEmail {
	return &ChangeEmail{opts}
}
