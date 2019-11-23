package passport

import "time"

const ConfirmationTokenValidity = 24 * time.Hour

type Confirmable struct {
	ConfirmationToken  string
	ConfirmationSentAt time.Time
	ConfirmedAt        time.Time
	// This is required when we allow users to change the email - we need
	// to verify the email before replacing the primary email to avoid
	// users from "chopping" other user's email.
	UnconfirmedEmail string
}

func (c Confirmable) IsValid() bool {
	return time.Since(c.ConfirmationSentAt) < ConfirmationTokenValidity
}

func NewConfirmable(email string) Confirmable {
	return Confirmable{
		ConfirmationToken:  uuid.Must(uuid.NewV4()),
		ConfirmationSentAt: time.Now(),
		UnconfirmedEmail:   email,
	}
}
