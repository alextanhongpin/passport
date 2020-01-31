package passport

import (
	"errors"
	"strings"
)

var (
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrTokenRequired = errors.New("token required")
)

// Token represents the value object for token.
type Token string

func (t Token) String() string {
	return string(t)
}

// Value returns the primitive type of the unique token.
func (t Token) Value() string {
	return string(t)
}

// Validate checks that the token is always set.
func (t Token) Validate() error {
	if t.Value() == "" {
		return ErrTokenRequired
	}
	return nil
}

// NewToken returns a new token.
func NewToken(value string) Token {
	return Token(strings.TrimSpace(value))
}
