package passport

var minPasswordLen = 8

type EncryptionAlgorithm func(plainText string) (SecurePassword, error)

type PlainTextPassword struct {
	minLength int
	value     string
	hasher    EncryptionAlgorithm
}

func (p *PlainTextPassword) Valid() bool {
	return !(len(p.Value()) < p.minLength)
}

func (p *PlainTextPassword) Validate() error {
	if p.Value() == "" {
		return ErrPasswordRequired
	}
	if valid := p.Valid(); !valid {
		return ErrPasswordTooShort
	}
	return nil
}

func (p *PlainTextPassword) Value() string {
	return p.value
}

func (p *PlainTextPassword) Equal(pwd Password) error {
	if p.Value() != pwd.Value() {
		return ErrPasswordDoNotMatch
	}
	return nil
}

func (p *PlainTextPassword) Encrypt() (SecurePassword, error) {
	return p.hasher(p.Value())
}

type PlainTextPasswordOption func(p *PlainTextPassword)

func MinLength(len int) PlainTextPasswordOption {
	return func(pwd *PlainTextPassword) {
		pwd.minLength = len
	}
}

func Hasher(hasher EncryptionAlgorithm) PlainTextPasswordOption {
	return func(pwd *PlainTextPassword) {
		pwd.hasher = hasher
	}
}

func NewPlainTextPassword(value string, opts ...PlainTextPasswordOption) *PlainTextPassword {
	pwd := PlainTextPassword{
		value:     value,
		minLength: minPasswordLen,
		hasher:    Argon2Factory,
	}
	for _, opt := range opts {
		opt(&pwd)
	}
	return &pwd
}
