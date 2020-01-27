package passport

import "errors"

var (
	// Confirmation.
	ErrConfirmationRequired = errors.New("confirmation required")

	// User.
	ErrUserNotFound = errors.New("user not found")
)
