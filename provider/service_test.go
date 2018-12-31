package provider

import (
	"errors"
	"testing"

	"github.com/go-pkgz/auth/token"
	"github.com/stretchr/testify/assert"
)

func TestRandToken(t *testing.T) {
	s1, err := randToken()
	assert.NoError(t, err)
	assert.NotEqual(t, "", s1)
	t.Log(s1)

	s2, err := randToken()
	assert.NoError(t, err)
	assert.NotEqual(t, "", s2)
	assert.NotEqual(t, s2, s1)
	t.Log(s2)
}

func TestSetAvatar(t *testing.T) {
	u, err := setAvatar(nil, token.User{Picture: "http://example.com/pic1.png"})
	assert.NoError(t, err, "nil ava allowed")
	assert.Equal(t, token.User{Picture: "http://example.com/pic1.png"}, u)

	u, err = setAvatar(mockAva{true, "http://example.com/pic1px.png"}, token.User{Picture: "http://example.com/pic1.png"})
	assert.NoError(t, err)
	assert.Equal(t, token.User{Picture: "http://example.com/pic1px.png"}, u)

	_, err = setAvatar(mockAva{false, ""}, token.User{Picture: "http://example.com/pic1.png"})
	assert.Error(t, err, "some error")
}

type mockAva struct {
	ok  bool
	res string
}

func (m mockAva) Put(u token.User) (avatarURL string, err error) {
	if !m.ok {
		return "", errors.New("some error")
	}
	return m.res, nil
}
