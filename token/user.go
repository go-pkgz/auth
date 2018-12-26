package token

import (
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc64"
	"io"
	"log"
	"regexp"

	"github.com/pkg/errors"
)

var reValidSha = regexp.MustCompile("^[a-fA-F0-9]{40}$")
var reValidCrc64 = regexp.MustCompile("^[a-fA-F0-9]{16}$")

const adminAttr = "admin" // predefined attribute key for bool isAdmin status

// User is the basic part of oauth data provided by service
type User struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Picture string `json:"picture"`
	IP      string `json:"ip,omitempty"`
	Email   string `json:"email,omitempty"`

	Attributes map[string]interface{} `json:"attrs,omitempty"`
}

// SetBoolAttr sets boolean attribute
func (u *User) SetBoolAttr(key string, val bool) {
	if u.Attributes == nil {
		u.Attributes = map[string]interface{}{}
	}
	u.Attributes[key] = val
}

// SetStrAttr sets string attribute
func (u *User) SetStrAttr(key string, val string) {
	if u.Attributes == nil {
		u.Attributes = map[string]interface{}{}
	}
	u.Attributes[key] = val
}

// BoolAttr gets boolean attribute
func (u *User) BoolAttr(key string) (bool, error) {
	r, ok := u.Attributes[key].(bool)
	if !ok {
		return false, errors.Errorf("invalid attribute type %T", u.Attributes[key])
	}
	return r, nil
}

// StrAttr gets string attribute
func (u *User) StrAttr(key string) (string, error) {
	r, ok := u.Attributes[key].(string)
	if !ok {
		return "", errors.Errorf("invalid attribute type %T", u.Attributes[key])
	}
	return r, nil
}

// SetAdmin is a shortcut to set "admin" attribute
func (u *User) SetAdmin(val bool) {
	u.SetBoolAttr(adminAttr, val)
}

// IsAdmin is a shortcut to get admin attribute
func (u *User) IsAdmin() bool {
	r, err := u.BoolAttr(adminAttr)
	if err != nil {
		return false
	}
	return r
}

// HashID tries to has val with hash.Hash and fallback to crc if needed
func HashID(h hash.Hash, val string) string {

	if reValidSha.MatchString(val) {
		return val // already hashed or empty
	}

	if _, err := io.WriteString(h, val); err != nil {
		// fail back to crc64
		log.Printf("[WARN] can't hash id %s, %s", val, err)
		if reValidCrc64.MatchString(val) {
			return val // already crced
		}
		return fmt.Sprintf("%x", crc64.Checksum([]byte(val), crc64.MakeTable(crc64.ECMA)))
	}
	return hex.EncodeToString(h.Sum(nil))
}
