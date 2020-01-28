package passport

type SecurePassword interface {
	Compare(Password) error
	Value() string
}
