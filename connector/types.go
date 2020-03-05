package connector

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
)

func PgDuplicateError(err error) bool {
	if pgerr, ok := err.(*pq.Error); ok {
		return pgerr.Code == "23505"
	}
	return false
}

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
