package passport

import (
	"errors"
	"time"

	uuid "github.com/satori/go.uuid"
)

// ErrConfirmationRequired indicates that the email requires confirmation.
var ErrConfirmationRequired = errors.New("confirmation required")

// ConfirmationTokenValidity represents the duration the confirmation token is
// valid.
const ConfirmationTokenValidity = 24 * time.Hour

// Confirmable holds the necessary data to perform confirmation on User's
// email.
type Confirmable struct {
	ConfirmationToken  string    `json:"confirmation_token,omitempty"`
	ConfirmationSentAt time.Time `json:"confirmation_sent_at,omitempty"`
	ConfirmedAt        time.Time `json:"confirmed_at,omitempty"`
	// This is required when we allow users to change the email - we need
	// to verify the email before replacing the primary email to avoid
	// users from "chopping" other user's email.
	UnconfirmedEmail string `json:"unconfirmed_email,omitempty"`
}

// Valid checks if the confirmation token is still within the validity
// period.
func (c Confirmable) Valid() bool {
	return time.Since(c.ConfirmationSentAt) < ConfirmationTokenValidity
}

// ValidateExpiry returns an error indicating the token has expired.
func (c Confirmable) ValidateExpiry() error {
	if valid := c.Valid(); !valid {
		return ErrTokenExpired
	}
	return nil
}

// Verified checks if the user's email is verified.
func (c Confirmable) Verified() bool {
	return !c.ConfirmedAt.IsZero() && c.UnconfirmedEmail == ""
}

// ValidateConfirmed returns an error indicating the email has not been
// verified.
func (c Confirmable) ValidateConfirmed() error {
	if verified := c.Verified(); !verified {
		return ErrConfirmationRequired
	}
	return nil
}

// NewConfirmable returns a new Confirmable.
func NewConfirmable(email string) Confirmable {
	return Confirmable{
		ConfirmationToken:  uuid.Must(uuid.NewV4()).String(),
		ConfirmationSentAt: time.Now(),
		UnconfirmedEmail:   email,
	}
}
