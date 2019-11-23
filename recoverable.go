package passport

import "time"

const RecoverableTokenValidity = 1 * time.Hour

type Recoverable struct {
	ResetPasswordToken  string
	ResetPasswordSentAt time.Time
	AllowPasswordChange bool
}

func (r Recoverable) IsValid() bool {
	return time.Since(r.ResetPasswordSentAt) < RecoverableTokenValidity
}
