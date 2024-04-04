package token

import (
	"crypto/sha1" //nolint
	"fmt"
	"net/http"
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

type mockBadHasher struct{}

func (m *mockBadHasher) Write([]byte) (n int, err error) { return 0, fmt.Errorf("err") }
func (m *mockBadHasher) Sum([]byte) []byte               { return nil }
func (m *mockBadHasher) Reset()                          {}
func (m *mockBadHasher) Size() int                       { return 0 }
func (m *mockBadHasher) BlockSize() int                  { return 0 }

func TestUser_HashIDWithCRC(t *testing.T) {
	tbl := []struct {
		id   string
		hash string
	}{
		{"myid", "e337514486e387ed"},
		{"", "914cd8098b8a2128"},
		{"blah blah", "a9d6c06bfd811649"},
		{"a9d6c06bfd811649", "a9d6c06bfd811649"},
	}

	for i, tt := range tbl {
		hh := &mockBadHasher{}
		assert.Equal(t, tt.hash, HashID(hh, tt.id), "case #%d", i)
	}
}

func TestUser_Attrs(t *testing.T) {
	u := User{Name: "test", IP: "127.0.0.1"}

	u.SetBoolAttr("k1", true)
	v := u.BoolAttr("k1")
	assert.True(t, v)

	u.SetBoolAttr("k1", false)
	v = u.BoolAttr("k1")
	assert.False(t, v)
	err := u.StrAttr("k1")
	assert.NotNil(t, err)

	u.SetStrAttr("k2", "v2")
	vs := u.StrAttr("k2")
	assert.Equal(t, "v2", vs)

	u.SetStrAttr("k2", "v22")
	vs = u.StrAttr("k2")
	assert.Equal(t, "v22", vs)

	vb := u.BoolAttr("k2")
	assert.False(t, vb)

	u.SetSliceAttr("ks", []string{"ss1", "ss2", "blah"})
	assert.Equal(t, []string{"ss1", "ss2", "blah"}, u.SliceAttr("ks"))
	assert.Equal(t, []string{}, u.SliceAttr("k2"), "not a slice")
}

func TestUser_Admin(t *testing.T) {
	u := User{Name: "test", IP: "127.0.0.1"}
	assert.False(t, u.IsAdmin())
	u.SetAdmin(true)
	assert.True(t, u.IsAdmin())
	u.SetAdmin(false)
	assert.False(t, u.IsAdmin())
}

func TestUser_PaidSubscriber(t *testing.T) {
	u := User{Name: "test"}
	assert.False(t, u.IsPaidSub())
	u.SetPaidSub(true)
	assert.True(t, u.IsPaidSub())
	u.SetPaidSub(false)
	assert.False(t, u.IsPaidSub())
}

func TestUser_GetUserInfo(t *testing.T) {
	r, err := http.NewRequest("GET", "http://blah.com", http.NoBody)
	assert.NoError(t, err)
	_, err = GetUserInfo(r)
	assert.EqualError(t, err, "user can't be parsed")

	r = SetUserInfo(r, User{Name: "test", ID: "id"})
	u, err := GetUserInfo(r)
	assert.NoError(t, err)
	assert.Equal(t, User{Name: "test", ID: "id"}, u)
}

func TestUser_MustGetUserInfo(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Log("recovered from panic")
		}
	}()

	r, err := http.NewRequest("GET", "http://blah.com", http.NoBody)
	assert.NoError(t, err)
	_ = MustGetUserInfo(r)
	assert.Fail(t, "should panic")

	r = SetUserInfo(r, User{Name: "test", ID: "id"})
	u := MustGetUserInfo(r)
	assert.NoError(t, err)
	assert.Equal(t, User{Name: "test", ID: "id"}, u)
}
