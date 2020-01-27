package passport

type Credential struct {
	Email    Email
	Password Password
}

func (c Credential) Valid() bool {
	return c.Email.Valid() && c.Password.Valid()
}

func (c Credential) Validate() error {
	if err := c.Email.Validate(); err != nil {
		return err
	}
	if err := c.Password.Validate(); err != nil {
		return err
	}
	return nil
}

func NewCredential(email, password string) Credential {
	return Credential{
		Email:    NewEmail(email),
		Password: NewPassword(password),
	}
}
