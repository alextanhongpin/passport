package passport_test

import (
	"testing"

	"github.com/alextanhongpin/passport"
	"github.com/stretchr/testify/assert"
)

func TestPassword(t *testing.T) {

	assert := assert.New(t)

	t.Run("when password is invalid", func(t *testing.T) {
		pwd := passport.NewPassword("")
		err := pwd.Validate()
		assert.NotNil(err)
		assert.Equal(passport.ErrPasswordRequired, err)
		assert.Equal([]byte{}, pwd.Byte())
		assert.Equal("", pwd.Value())
		assert.Nil(pwd.Equal(pwd))
	})
}
