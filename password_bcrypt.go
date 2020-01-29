package passport

import "golang.org/x/crypto/bcrypt"

type BcryptPassword struct {
	cost int
}

func (b *BcryptPassword) Compare(cipherText, plainText []byte) error {
	return bcrypt.CompareHashAndPassword(cipherText, plainText)
}

func (b *BcryptPassword) Encode(plainText []byte) (string, error) {
	cipherText, err := bcrypt.GenerateFromPassword(plainText, b.cost)
	return string(cipherText), err
}

func NewBcryptPassword(cost int) *BcryptPassword {
	return &BcryptPassword{cost: cost}
}
