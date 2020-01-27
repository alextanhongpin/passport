package passport

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

// RecoverableTokenValidity represents the duration the reset password token is
// valid.
const RecoverableTokenValidity = 1 * time.Hour

// Recoverable holds the data to reset the User's password.
type Recoverable struct {
	ResetPasswordToken  string    `json:"reset_password_token,omitempty"`
	ResetPasswordSentAt time.Time `json:"reset_password_sent_at,omitempty"`
	AllowPasswordChange bool      `json:"allow_password_change,omitempty"`
}

// Valid checks if the reset password token is within the validity period.
func (r Recoverable) Valid() bool {
	return time.Since(r.ResetPasswordSentAt) < RecoverableTokenValidity
}

func (r Recoverable) Validate() error {
	if valid := r.Valid(); !valid {
		return ErrTokenExpired
	}
	return nil
}

// NewRecoverable returns a new Recoverable.
func NewRecoverable() Recoverable {
	return Recoverable{
		// Instead of using the Postgres UUID, we set it here.
		// This allows us to change the implementation at the
		// application level.
		ResetPasswordToken:  uuid.Must(uuid.NewV4()).String(),
		ResetPasswordSentAt: time.Now(),
		AllowPasswordChange: true,
	}
}
