package passport

import "context"

type Repository interface {
	Create(ctx context.Context, email, password string) (*User, error)
	UpdateRecoverable(ctx context.Context, email string, recoverable Recoverable) (bool, error)
	UpdateConfirmable(ctx context.Context, email string, confirmable Confirmable) (bool, error)
	UpdatePassword(ctx context.Context, userID, encryptedPassword string) (bool, error)
	WithEmail(ctx context.Context, email string) (*User, error)
	WithResetPasswordToken(ctx context.Context, token string) (*User, error)
	WithConfirmationToken(ctx context.Context, token string) (*User, error)
	HasEmail(ctx context.Context, email string) (bool, error)
}
