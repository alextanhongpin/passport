package connector

import (
	"database/sql"
	"time"
)

func NewNullString(str string) sql.NullString {
	if str == "" {
		return sql.NullString{}
	}
	return sql.NullString{
		Valid:  true,
		String: str,
	}
}

func NewNullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{
		Valid: true,
		Time:  t,
	}
}
