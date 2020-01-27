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

type Token string

func (t Token) String() string {
	return string(t)
}

func (t Token) Value() string {
	return string(t)
}

func (t Token) Validate() error {
	if t.Value() == "" {
		return ErrTokenRequired
	}
	return nil
}

func NewToken(value string) Token {
	return Token(strings.TrimSpace(value))
}
