package passport

import "errors"

var (
	// Confirmation.
	ErrConfirmationRequired = errors.New("confirmation required")

	// Email.
	ErrEmailExists            = errors.New("email exists")
	ErrEmailInvalid           = errors.New("email invalid")
	ErrEmailNotFound          = errors.New("email not found")
	ErrEmailOrPasswordInvalid = errors.New("email or password is invalid")
	ErrEmailRequired          = errors.New("email required")
	ErrEmailVerified          = errors.New("email verified")

	// User.
	ErrUserIDRequired = errors.New("user_id required")
	ErrUserNotFound   = errors.New("user not found")

	// Password.
	ErrPasswordChangeNotAllowed = errors.New("password change not allowed")
	ErrPasswordDoNotMatch       = errors.New("password do not match")
	ErrPasswordRequired         = errors.New("password required")
	ErrPasswordTooShort         = errors.New("password too short")
	ErrPasswordUsed             = errors.New("password cannot be reused")

	// Token.
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRequired = errors.New("token required")
)
