package provider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

func TestDirect_LoginHandler(t *testing.T) {
	d := DirectHandler{
		ProviderName: "test",
		CredChecker:  &mockCredsChecker{ok: true},
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	assert.Equal(t, "test", d.Name())

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"myuser","id":"test_ed6307123e30cc7682328522d1d090d9c7525b32","picture":""}`+"\n", rr.Body.String())

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	claims, err := d.TokenService.Parse(c.Value)
	require.NoError(t, err)
	t.Logf("%+v", claims)
	assert.Equal(t, "xyz123", claims.Audience)
	assert.Equal(t, "iss-test", claims.Issuer)
	assert.True(t, claims.ExpiresAt > time.Now().Unix())
	assert.Equal(t, "myuser", claims.User.Name)
}

func TestDirect_LoginHandlerFailed(t *testing.T) {
	d := DirectHandler{
		ProviderName: "test",
		CredChecker:  nil,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"no credential checker"}`+"\n", rr.Body.String())

	d.CredChecker = &mockCredsChecker{err: errors.New("some err"), ok: false}
	handler = http.HandlerFunc(d.LoginHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to check user credentials"}`+"\n", rr.Body.String())

	d.CredChecker = &mockCredsChecker{err: nil, ok: false}
	handler = http.HandlerFunc(d.LoginHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 403, rr.Code)
	assert.Equal(t, `{"error":"incorrect user or password"}`+"\n", rr.Body.String())

}
func TestDirect_Logout(t *testing.T) {
	d := DirectHandler{
		ProviderName: "test",
		CredChecker:  &mockCredsChecker{ok: true},
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, 2, len(rr.Header()["Set-Cookie"]))

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)

	c, err = request.Cookie("XSRF-TOKEN")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)
}

func TestDirect_AuthHandler(t *testing.T) {
	d := DirectHandler{}
	handler := http.HandlerFunc(d.AuthHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/callback", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
}

func TestDirect_CredChecker(t *testing.T) {
	ch := CredCheckerFunc(func(user string, password string) (ok bool, err error) {
		if user == "dev" && password == "password" {
			return true, nil
		}
		return false, nil
	})

	ok, err := ch.Check("user", "blah")
	assert.NoError(t, err)
	assert.False(t, ok)

	ok, err = ch.Check("dev", "password")
	assert.NoError(t, err)
	assert.True(t, ok)
}

type mockCredsChecker struct {
	ok  bool
	err error
}

func (m *mockCredsChecker) Check(user, password string) (ok bool, err error) { return m.ok, m.err }
