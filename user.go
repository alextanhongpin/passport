package passport

import (
	"errors"
	"time"
)

var ErrUserNotFound = errors.New("user not found")

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

// Rather than setting value objects for Entity, use primitives, but return
// value objects through methods instead. This makes sense, since most entity
// operation will involve storing the values into the database, which requires
// primitives type. If we use value object instead, we need to implement value
// and scanner to satisfy the sql implementation.
func (u *User) SecurePassword() SecurePassword {
	return SecurePassword(u.EncryptedPassword)
}

func (u *User) UserID() UserID {
	return UserID(u.ID)
}
