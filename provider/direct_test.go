package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-pkgz/auth/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/token"
)

func TestDirect_LoginHandler(t *testing.T) {
	d := DirectHandler{
		ProviderName: "test",
		CredChecker:  &mockCredsChecker{ok: true},
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(id string) (string, error) { return "secret", nil }),
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
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"myuser","id":"","picture":""}`+"\n", rr.Body.String())

	request := &http.Request{Header: http.Header{"Cookie": rr.HeaderMap["Set-Cookie"]}}
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

type mockCredsChecker struct {
	ok  bool
	err error
}

func (m *mockCredsChecker) Check(user, password string) (ok bool, err error) { return m.ok, m.err }
