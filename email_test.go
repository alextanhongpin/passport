package passport_test

import (
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/stretchr/testify/assert"
)

func TestEmail(t *testing.T) {
	assert := assert.New(t)
	var (
		emptyEmail   = passport.NewEmail("")
		invalidEmail = passport.NewEmail("john.doe@")
		validEmail   = passport.NewEmail("a@b.com")
	)
	assert.Equal(passport.ErrEmailRequired, emptyEmail.Validate())
	assert.Equal(passport.ErrEmailInvalid, invalidEmail.Validate())
	assert.Nil(validEmail.Validate())
}
