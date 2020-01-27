package passport

type SecurePassword interface {
	Compare(Password) error
	Value() string
}

// // SecurePassword is a value object to represent encrypted password.
// type SecurePassword string
//
// // Compare checks if the encrypted password matches the plaintext password.
// func (s SecurePassword) Compare(password Password) bool {
//         match, _ := passwd.Compare(password.Value(), s.Value())
//         return match
// }
//
// // Value returns the password as primitive type.
// func (s SecurePassword) Value() string {
//         return string(s)
// }
//
// // NewSecurePassword returns an encrypted password from plaintext password.
// func NewSecurePassword(password string) (SecurePassword, error) {
//         cipher, err := passwd.Encrypt(password)
//         return SecurePassword(cipher), err
// }
