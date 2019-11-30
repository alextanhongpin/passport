package passport

import (
	"time"
)

// User represents the authenticatable Entity.
type User struct {
	ID                string    `json:"id,omitempty"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	Email             string    `json:"email,omitempty"`
	EncryptedPassword string    `json:"encrypted_password,omitempty"`

	// Allow account to be recovered by resetting the password.
	Recoverable

	// Allow emails to be confirmed, especially when changing new email.
	Confirmable

	// Allow account information (client ip, user agent, sign in count) to
	// be tracked.
	// Trackable

	// Allows additionable information to be added to the user struct.
	Extra Extra `json:"extra,omitempty"`
}

// IsConfirmationRequired checks if the User's email has been verified or not.
func (u User) IsConfirmationRequired() bool {
	return !u.Confirmable.IsVerified()
}
