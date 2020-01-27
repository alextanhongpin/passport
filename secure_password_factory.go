package passport

type securePasswordFactory struct{}

func (s *securePasswordFactory) FromUser(user User) SecurePassword {
	return SecurePassword(user.EncryptedPassword)
}

func SecurePasswordFactory() *securePasswordFactory {
	return &securePasswordFactory{}
}
