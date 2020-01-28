package passport

import "golang.org/x/crypto/bcrypt"

type BcryptPassword struct {
	value string
}

func (b *BcryptPassword) Value() string {
	return string(b.value)
}

func (b *BcryptPassword) Compare(pwd Password) error {
	return bcrypt.CompareHashAndPassword([]byte(b.Value()), []byte(pwd.Value()))
}

func NewBcryptPassword(cipher string) *BcryptPassword {
	return &BcryptPassword{value: cipher}
}

func BcryptFactory(password string) (SecurePassword, error) {
	cipher, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return &BcryptPassword{value: string(cipher)}, err
}
