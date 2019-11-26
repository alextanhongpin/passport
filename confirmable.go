package passport

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

const ConfirmationTokenValidity = 24 * time.Hour

// Confirmable holds the necessary data to perform confirmation on user's
// email.
type Confirmable struct {
	ConfirmationToken  string
	ConfirmationSentAt time.Time
	ConfirmedAt        time.Time
	// This is required when we allow users to change the email - we need
	// to verify the email before replacing the primary email to avoid
	// users from "chopping" other user's email.
	UnconfirmedEmail string
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
