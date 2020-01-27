package passport

import (
	"errors"
	"strings"
)

var ErrUserIDRequired = errors.New("user_id required")

type UserID string

func (u UserID) String() string {
	return string(u)
}

func (u UserID) Validate() error {
	if u.Value() == "" {
		return ErrUserIDRequired
	}
	return nil
}

func (u UserID) Value() string {
	return string(u)
}

type userIDFactory struct{}

func UserIDFactory() *userIDFactory {
	return &userIDFactory{}
}

func (u *userIDFactory) FromString(userID string) UserID {
	return UserID(strings.TrimSpace(userID))
}
