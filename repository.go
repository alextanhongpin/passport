package passport

import "context"

type (
	Create func(ctx context.Context, email, password string) (*User, error)

	Find func(ctx context.Context, id string) (*User, error)

	HasEmail func(ctx context.Context, email string) (bool, error)

	UpdateConfirmable func(ctx context.Context, email string, confirmable Confirmable) (bool, error)

	UpdatePassword func(ctx context.Context, userID, encryptedPassword string) (bool, error)

	UpdateRecoverable func(ctx context.Context, email string, recoverable Recoverable) (bool, error)

	WithConfirmationToken func(ctx context.Context, token string) (*User, error)

	WithEmail func(ctx context.Context, email string) (*User, error)

	WithResetPasswordToken func(ctx context.Context, token string) (*User, error)
)
