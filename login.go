package passport

import (
	"context"
	"database/sql"
	"errors"
)

type login interface {
	Exec(context.Context, Credential) (*User, error)
}

type readOnlyUserRepository interface {
	WithEmail(ctx context.Context, email string) (*User, error)
}

type Login struct {
	users readOnlyUserRepository
}

func (l *Login) Exec(ctx context.Context, cred Credential) (*User, error) {
	if err := cred.Validate(); err != nil {
		return nil, err
	}
	user, err := l.findUser(ctx, cred.Email)
	if err != nil {
		return nil, err
	}

	if err := l.checkPasswordMatch(
		SecurePassword(user.EncryptedPassword),
		cred.Password,
	); err != nil {
		return nil, err
	}

	if err := user.Confirmable.ValidateConfirmed(); err != nil {
		return nil, err
	}

	return user, nil
}

func (l *Login) findUser(ctx context.Context, email Email) (*User, error) {
	user, err := l.users.WithEmail(ctx, email.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (l *Login) checkPasswordMatch(encrypted SecurePassword, password Password) error {
	if match := encrypted.Compare(password); !match {
		return ErrEmailOrPasswordInvalid
	}
	return nil
}

func NewLogin(repository readOnlyUserRepository) *Login {
	return &Login{repository}
}
