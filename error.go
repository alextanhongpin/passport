package passport

import "errors"

var (
	// Confirmation.
	ErrConfirmationRequired = errors.New("confirmation required")

	// User.
	ErrUserIDRequired = errors.New("user_id required")
	ErrUserNotFound   = errors.New("user not found")

	// Token.
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRequired = errors.New("token required")
)
