package passport

import (
	"context"
	"database/sql"
	"errors"
)

type (
	loginRepository interface {
		WithEmail(ctx context.Context, email string) (*User, error)
	}

	LoginOptions struct {
		Repository loginRepository
		Comparer   passwordComparer
	}

	// Options are good, since we don't need to care about the sequence,
	// and we can easily reuse them by mocking part of them. They can also
	// separate private methods from dependencies injection.
	// An added advantage is it becomes easier to decorate dependencies,
	// and simplify factory methods.
	Login struct {
		options LoginOptions
	}
)

// Exec executes the Login use case.
func (l *Login) Exec(ctx context.Context, cred Credential) (*User, error) {
	if err := l.validate(cred); err != nil {
		return nil, err
	}

	user, err := l.findUser(ctx, cred.Email)
	if err != nil {
		return nil, err
	}

	if err := l.checkPasswordMatch(
		user.EncryptedPassword,
		cred.Password,
	); err != nil {
		return nil, err
	}

	if err := l.checkUserConfirmed(user.Confirmable); err != nil {
		return nil, err
	}

	return user, nil
}

func (l *Login) validate(cred Credential) error {
	return cred.Validate()
}

func (l *Login) findUser(ctx context.Context, email Email) (*User, error) {
	user, err := l.options.Repository.WithEmail(ctx, email.Value())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (l *Login) checkPasswordMatch(cipherText, plainText Password) error {
	if err := l.options.Comparer.Compare(
		cipherText.Byte(),
		plainText.Byte(),
	); err != nil {
		return ErrEmailOrPasswordInvalid
	}
	return nil
}

func (l *Login) checkUserConfirmed(confirmable Confirmable) error {
	return confirmable.ValidateConfirmed()
}

func NewLogin(options LoginOptions) *Login {
	return &Login{options}
}
