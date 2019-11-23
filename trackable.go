package passport

import "time"

type Trackable struct {
	SignInCount            int
	CurrentSignInAt        time.Time
	CurrentSignInIP        string
	CurrentSignInUserAgent string
	LastSignInAt           time.Time
	LastSignInIP           string
	LastSignInUserAgent    string
	LastSignOutAt          time.Time
	LastSignOutIP          string
	LastSignOutUserAgent   string
}
