package passport

type User struct {
	ID string
	// This must be nullable, and it must be unique too. We cannot set this first, because I can register another user, but have not validated my email. In other words, I can steal someone's identity.
	Email             string
	EmailVerified     bool
	EncryptedPassword string

	// Allow account to be recovered by resetting the password.
	Recoverable

	// Allow emails to be confirmed, especially when changing new email.
	Confirmable

	// Allow account information (client ip, user agent, sign in count) to
	// be tracked.
	Trackable
}
