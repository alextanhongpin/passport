package passport

import (
	"context"
	"database/sql"
	"errors"
)

type ChangeEmail func(ctx context.Context, currentUserID UserID, email Email) (string, error)

type (
	changeEmailRepository interface {
		HasEmail(ctx context.Context, email string) (bool, error)
		Find(ctx context.Context, id string) (*User, error)
		UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
	}
)

type ChangeEmailRepository struct {
	HasEmailFunc          HasEmail
	FindFunc              Find
	UpdateConfirmableFunc UpdateConfirmable
}

func (c *ChangeEmailRepository) HasEmail(ctx context.Context, email string) (bool, error) {
	return c.HasEmailFunc(ctx, email)
}

func (c *ChangeEmailRepository) UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error) {
	return c.UpdateConfirmableFunc(ctx, email, confirmable)
}

func (c *ChangeEmailRepository) Find(ctx context.Context, id string) (*User, error) {
	return c.FindFunc(ctx, id)
}

func NewChangeEmail(users changeEmailRepository) ChangeEmail {
	validate := func(userID UserID, email Email) error {
		if err := email.Validate(); err != nil {
			return err
		}
		if err := userID.Validate(); err != nil {
			return err
		}
		return nil
	}

	checkEmailExists := func(ctx context.Context, email Email) error {
		exists, err := users.HasEmail(ctx, email.Value())
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if exists {
			return ErrEmailExists
		}
		return nil
	}

	findUser := func(ctx context.Context, userID UserID) (*User, error) {
		user, err := users.Find(ctx, userID.Value())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	return func(ctx context.Context, currentUserID UserID, email Email) (string, error) {
		if err := validate(currentUserID, email); err != nil {
			return "", err
		}
		if err := checkEmailExists(ctx, email); err != nil {
			return "", err
		}

		user, err := findUser(ctx, currentUserID)
		if err != nil {
			return "", err
		}

		currEmail := NewEmail(user.Email)
		if err := currEmail.Validate(); err != nil {
			return "", err
		}

		var confirmable = NewConfirmable(email.Value())
		if _, err = users.UpdateConfirmable(ctx, currEmail.Value(), confirmable); err != nil {
			return "", err
		}

		// Return the confirmable in order to send the email.
		return confirmable.ConfirmationToken, nil
	}
}
