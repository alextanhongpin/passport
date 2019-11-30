package passport

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

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

// IsValid checks if the confirmation token is still within the validity
// period.
func (c Confirmable) IsValid() bool {
	return time.Since(c.ConfirmationSentAt) < ConfirmationTokenValidity
}

// IsVerified checks if the user's email is verified.
func (c Confirmable) IsVerified() bool {
	return !c.ConfirmedAt.IsZero() && c.UnconfirmedEmail == ""
}

// NewConfirmable returns a new Confirmable.
func NewConfirmable(email string) Confirmable {
	return Confirmable{
		ConfirmationToken:  uuid.Must(uuid.NewV4()).String(),
		ConfirmationSentAt: time.Now(),
		UnconfirmedEmail:   email,
	}
}
