package passport

import uuid "github.com/satori/go.uuid"

type UUIDTokenGenerator struct{}

func (u *UUIDTokenGenerator) Generate() (string, error) {
	token, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return token.String(), nil
}

func NewTokenGenerator() *UUIDTokenGenerator {
	return &UUIDTokenGenerator{}
}
