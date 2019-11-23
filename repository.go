package passport

import "context"

type Repository interface {
	Create(ctx context.Context, email, password string) (User, error)
	UpdateRecoverable(User, Recoverable) (bool, error)
	UpdateConfirmable(User, Confirmable) (bool, error)
	UpdatePassword(user User, encryptedPassword string) (bool, error)
	WithEmail(ctx context.Context, email string) (User, error)
	WithResetPasswordToken(token string) (User, error)
	WithConfirmationToken(token string) (User, error)
	HasEmail(email string) (bool, error)
}
