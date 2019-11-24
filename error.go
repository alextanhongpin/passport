package passport

import "errors"

var (
	ErrConfirmationRequired     = errors.New("confirmation required")
	ErrEmailNotFound            = errors.New("email not found")
	ErrEmailInvalid             = errors.New("email invalid")
	ErrEmailRequired            = errors.New("email required")
	ErrEmailVerified            = errors.New("email verified")
	ErrEmailExists              = errors.New("email exists")
	ErrPasswordRequired         = errors.New("password required")
	ErrPasswordUsed             = errors.New("password cannot be reused")
	ErrPasswordTooShort         = errors.New("password too short")
	ErrPasswordDoNotMatch       = errors.New("password do not match")
	ErrPasswordChangeNotAllowed = errors.New("password change not allowed")
	ErrEmailOrPasswordInvalid   = errors.New("email or password is invalid")
	ErrTokenRequired            = errors.New("token is required")
	ErrTokenInvalid             = errors.New("token invalid")
	ErrTokenNotFound            = errors.New("token not found")
	ErrTokenExpired             = errors.New("token expired")
)
