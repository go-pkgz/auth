package token

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasic_BasicAuth(t *testing.T) {
	ch := BasicAuthFunc(func(user, passwd string) (bool, User, error) {
		if passwd == "test_p" {
			return true, User{Name: user, Role: "test_r"}, nil
		}
		return false, User{}, errors.New("credentials check failed")
	})

	ok, ui, err := ch.Check("test_u", "test_p")
	assert.True(t, ok)
	assert.Nil(t, err)
	assert.Equal(t, ui.Name, "test_u")
	assert.Equal(t, ui.Role, "test_r")

	ok, ui, err = ch.Check("test_u", "test_p_fake")
	assert.True(t, !ok)
	assert.NotNil(t, err)
	assert.Equal(t, ui.Name, "")

}
