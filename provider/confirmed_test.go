package provider

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

var (
	testConfirmedToken      = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.D8AvAunK7Tj-P6P56VyaoZ-hyA6U8duZ9HV8-ACEya8`
	testConfirmedBadIDToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJibGFoQHVzZXIuY29tIn19.hB91-kyY9-Q2Ln6IJGR9StQi-QQiXYu8SV31YhOoTbc`
)

func TestConfirmHandler_LoginSendConfirm(t *testing.T) {

	emailer := mockSender{}
	e := ConfirmHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   &emailer,
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user=test123&site=remark42", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "blah@user.com", emailer.to)
	assert.Contains(t, emailer.text, "test123 blah@user.com remark42 token:")

	tknStr := strings.Split(emailer.text, " token:")[1]
	tkn, err := e.TokenService.Parse(tknStr)
	assert.NoError(t, err)
	t.Logf("%s %+v", tknStr, tkn)
	assert.Equal(t, "test123::blah@user.com", tkn.Handshake.ID)
	assert.Equal(t, "remark42", tkn.Audience)
	assert.True(t, tkn.ExpiresAt > tkn.NotBefore)

	assert.Equal(t, "test", e.Name())
}

func TestConfirmHandler_LoginAcceptConfirm(t *testing.T) {
	e := ConfirmHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedToken), nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"test123","id":"test_63c1017838e567a526800790805eae4dc975402b","picture":""}`+"\n", rr.Body.String())

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	claims, err := e.TokenService.Parse(c.Value)
	require.NoError(t, err)
	t.Logf("%+v", claims)
	assert.Equal(t, "remark42", claims.Audience)
	assert.Equal(t, "iss-test", claims.Issuer)
	assert.True(t, claims.ExpiresAt > time.Now().Unix())
	assert.Equal(t, "test123", claims.User.Name)
	assert.Equal(t, true, claims.SessionOnly)
}

func TestConfirm_LoginHandlerFailed(t *testing.T) {
	emailer := mockSender{}
	d := ConfirmHandler{
		ProviderName: "test",
		Sender:       &emailer,
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
	req, err := http.NewRequest("GET", "/login?user=myuser&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 400, rr.Code)
	assert.Equal(t, `{"error":"can't get user and address"}`+"\n", rr.Body.String())

	d.Sender = &mockSender{err: errors.New("some err")}
	handler = http.HandlerFunc(d.LoginHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to send confirmation"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token=bad", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedBadIDToken, nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, `{"error":"invalid handshake token"}`+"\n", rr.Body.String())

	d.Template = `{{.Blah}}`
	d.Sender = &mockSender{}
	handler = http.HandlerFunc(d.LoginHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, `{"error":"can't execute confirmation template"}`+"\n", rr.Body.String())
}

func TestConfirm_AuthHandler(t *testing.T) {
	d := ConfirmHandler{}
	handler := http.HandlerFunc(d.AuthHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/callback", nil)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
}

func TestConfirm_Logout(t *testing.T) {
	d := ConfirmHandler{
		ProviderName: "test",
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

type mockSender struct {
	err error

	to   string
	text string
}

func (m *mockSender) Send(to string, text string) error {
	if m.err != nil {
		return m.err
	}
	m.to = to
	m.text = text
	return nil
}
