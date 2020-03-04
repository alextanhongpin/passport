package usecase

type tokenGenerator interface {
	Generate() (string, error)
}

type (
	passwordEncoder interface {
		Encode(password []byte) (string, error)
	}

	passwordComparer interface {
		Compare(hash, password []byte) error
	}

	passwordEncoderComparer interface {
		passwordEncoder
		passwordComparer
	}
)
