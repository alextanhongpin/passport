package passport

import (
	"context"
	"time"

	"github.com/alextanhongpin/passwd"
)

type User struct {
	// This must be nullable, and it must be unique too. We cannot set this first, because I can register another user, but have not validated my email. In other words, I can steal someone's identity.
	Email             string
	EmailVerified     bool
	EncryptedPassword string

	// Recoverable.
	Recoverable

	// Confirmable.
	Confirmable

	// Trackable.
	SignInCount            int
	CurrentSignInAt        time.Time
	CurrentSignInIP        string
	CurrentSignInUserAgent string
	LastSignInAt           time.Time
	LastSignInIP           string
	LastSignInUserAgent    string
	LastSignOutAt          time.Time
	LastSignOutIP          string
	LastSignOutUserAgent   string
}

type Recoverable struct {
	ResetPasswordToken  string
	ResetPasswordSentAt time.Time
	AllowPasswordChange bool
}

type Confirmable struct {
	// Confirmable.
	ConfirmationToken  string
	ConfirmationSentAt time.Time
	ConfirmedAt        time.Time
	// UnconfirmedEmail   string
}

func (u *User) ComparePassword(password string) (bool, error) {
	return passwd.Compare(u.EncryptedPassword, password)
}

type UserRepository interface {
	Create(context.Context, User)
	WithEmail(ctx context.Context, email string)
	Track(ctx context.Context, user User, clientIP string, userAgent string)
}
