package passport

import "context"

type Repository interface {
	Create(ctx context.Context, email, password string) (*User, error)
	UpdateRecoverable(context.Context, User, Recoverable) (bool, error)
	UpdateConfirmable(context.Context, User, Confirmable) (bool, error)
	UpdatePassword(ctx context.Context, user User, encryptedPassword string) (bool, error)
	WithEmail(ctx context.Context, email string) (*User, error)
	WithResetPasswordToken(ctx context.Context, token string) (*User, error)
	WithConfirmationToken(ctx context.Context, token string) (*User, error)
	HasEmail(ctx context.Context, email string) (bool, error)
}
