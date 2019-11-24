package passport

import "time"

const (
	// ConfirmationPeriodValidity represents the duration the user is
	// allowed to login the application without verifying the email (set to
	// 1 month) - after this period, the account will be deactivated after
	// 6 months (or depending on your requirement).
	ConfirmationPeriodValidity = 30 * 24 * time.Hour
)

type User struct {
	ID                string
	CreatedAt         time.Time
	Email             string
	EncryptedPassword string

	// Allow account to be recovered by resetting the password.
	Recoverable

	// Allow emails to be confirmed, especially when changing new email.
	Confirmable

	// Allow account information (client ip, user agent, sign in count) to
	// be tracked.
	Trackable

	// Allows additionable information to be added to the user struct.
	Extra Extra
}

func (u User) IsConfirmationRequired() bool {
	if u.Confirmable.IsVerified() {
		return false
	}
	return time.Since(u.CreatedAt) > ConfirmationPeriodValidity
}
