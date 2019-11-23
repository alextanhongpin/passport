package passport

import "context"

type Session struct {
}

type SessionRepository interface {
	Create(context.Context, Session)
}

type SessionRepositoryCache interface {
}
