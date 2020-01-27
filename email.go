package passport

import (
	"strings"
)

type Email string

func (e Email) Valid() bool {
	return emailRegex.MatchString(string(e))
}

func (e Email) String() string {
	return string(e)
}

func (e Email) Value() string {
	return string(e)
}

func NewEmail(email string) Email {
	return Email(strings.TrimSpace(email))
}
