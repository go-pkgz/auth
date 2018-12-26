package token

import (
	"crypto/sha1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser_HashID(t *testing.T) {
	tbl := []struct {
		id   string
		hash string
	}{
		{"myid", "6e34471f84557e1713012d64a7477c71bfdac631"},
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"blah blah", "135a1e01bae742c4a576b20fd41a683f6483ca43"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}

	for i, tt := range tbl {
		hh := sha1.New()
		assert.Equal(t, tt.hash, HashID(hh, tt.id), "case #%d", i)
	}
}

func TestUser_Attrs(t *testing.T) {
	u := User{Name: "test", IP: "127.0.0.1"}

	u.SetBoolAttr("k1", true)
	v, err := u.BoolAttr("k1")
	assert.NoError(t, err)
	assert.True(t, v)

	u.SetBoolAttr("k1", false)
	v, err = u.BoolAttr("k1")
	assert.NoError(t, err)
	assert.False(t, v)
	_, err = u.StrAttr("k1")
	assert.NotNil(t, err)

	u.SetStrAttr("k2", "v2")
	vs, err := u.StrAttr("k2")
	assert.NoError(t, err)
	assert.Equal(t, "v2", vs)

	u.SetStrAttr("k2", "v22")
	vs, err = u.StrAttr("k2")
	assert.NoError(t, err)
	assert.Equal(t, "v22", vs)

	_, err = u.BoolAttr("k2")
	assert.NotNil(t, err)
}

func TestUser_Admin(t *testing.T) {
	u := User{Name: "test", IP: "127.0.0.1"}
	assert.False(t, u.IsAdmin())
	u.SetAdmin(true)
	assert.True(t, u.IsAdmin())
	u.SetAdmin(false)
	assert.False(t, u.IsAdmin())
}
