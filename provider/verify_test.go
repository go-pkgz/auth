package provider

import (
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

// nolint
var (
	testConfirmedToken      = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.D8AvAunK7Tj-P6P56VyaoZ-hyA6U8duZ9HV8-ACEya8`
	testConfirmedBadIDToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJibGFoQHVzZXIuY29tIn19.hB91-kyY9-Q2Ln6IJGR9StQi-QQiXYu8SV31YhOoTbc`
	testConfirmedGravatar   = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJncmF2YTo6ZWVmcmV0c291bEBnbWFpbC5jb20ifX0.yQTtG7neX3YjLZ-SGeiiNmwNfJWA7nR50KAxDw834XE`
	testConfirmedExpired    = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTU2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.bCFMAwCg1_l4yuEzFYzd0q9PstY-auHe2rwLqltffqo`
)

func TestVerifyHandler_LoginSendConfirm(t *testing.T) {

	emailer := mockSender{}
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   SenderFunc(emailer.Send),
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user=test123&site=remark42", http.NoBody)
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

func TestVerifyHandler_LoginSendConfirmRejected(t *testing.T) {

	emailer := mockSender{}
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   SenderFunc(emailer.Send),
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	badUser := "%3C%21DOCTYPE%20html%3E%20%0A%3Chtml%3E%20%0A%3Chead%3E%0A%3Cmeta%20name%3D%22viewport%22%20content%3D%22width%3Ddevice-width%2C%20initial-scale%3D1%22%3E%0A%3Ctitle%3E%20Login%20Page%20%3C%2Ftitle%3E%0A%3Cstyle%3E%20%0ABody%20%7B%0A%20%20font-family%3A%20Calibri%2C%20Helvetica%2C%20sans-serif%3B%0A%20%20background-color%3A%20pink%3B%0A%7D%0Abutton%20%7B%20%0A%20%20%20%20%20%20%20background-color%3A%20%234CAF50%3B%20%0A%20%20%20%20%20%20%20width%3A%20100%25%3B%0A%20%20%20%20%20%20%20%20color%3A%20orange%3B%20%0A%20%20%20%20%20%20%20%20padding%3A%2015px%3B%20%0A%20%20%20%20%20%20%20%20margin%3A%2010px%200px%3B%20%0A%20%20%20%20%20%20%20%20border%3A%20none%3B%20%0A%20%20%20%20%20%20%20%20cursor%3A%20pointer%3B%20%0A%20%20%20%20%20%20%20%20%20%7D%20%0A%20form%20%7B%20%0A%20%20%20%20%20%20%20%20border%3A%203px%20solid%20%23f1f1f1%3B%20%0A%20%20%20%20%7D%20%0A%20input%5Btype%3Dtext%5D%2C%20input%5Btype%3Dpassword%5D%20%7B%20%0A%20%20%20%20%20%20%20%20width%3A%20100%25%3B%20%0A%20%20%20%20%20%20%20%20margin%3A%208px%200%3B%0A%20%20%20%20%20%20%20%20padding%3A%2012px%2020px%3B%20%0A%20%20%20%20%20%20%20%20display%3A%20inline-block%3B%20%0A%20%20%20%20%20%20%20%20border%3A%202px%20solid%20green%3B%20%0A%20%20%20%20%20%20%20%20box-sizing%3A%20border-box%3B%20%0A%20%20%20%20%7D%0A%20button%3Ahover%20%7B%20%0A%20%20%20%20%20%20%20%20opacity%3A%200.7%3B%20%0A%20%20%20%20%7D%20%0A%20%20.cancelbtn%20%7B%20%0A%20%20%20%20%20%20%20%20width%3A%20auto%3B%20%0A%20%20%20%20%20%20%20%20padding%3A%2010px%2018px%3B%0A%20%20%20%20%20%20%20%20margin%3A%2010px%205px%3B%0A%20%20%20%20%7D%20%0A%20%20%20%20%20%20%0A%20%20%20%0A%20.container%20%7B%20%0A%20%20%20%20%20%20%20%20padding%3A%2025px%3B%20%0A%20%20%20%20%20%20%20%20background-color%3A%20lightblue%3B%0A%20%20%20%20%7D%20%0A%3C%2Fstyle%3E%20%0A%3C%2Fhead%3E%20%20%0A%3Cbody%3E%20%20%0A%20%20%20%20%3Ccenter%3E%20%3Ch1%3E%20Student%20Login%20Form%20%3C%2Fh1%3E%20%3C%2Fcenter%3E%20%0A%20%20%20%20%3Cform%3E%0A%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%22%3E%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Clabel%3EUsername%20%3A%20%3C%2Flabel%3E%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20type%3D%22text%22%20placeholder%3D%22Enter%20Username%22%20name%3D%22username%22%20required%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Clabel%3EPassword%20%3A%20%3C%2Flabel%3E%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20type%3D%22password%22%20placeholder%3D%22Enter%20Password%22%20name%3D%22password%22%20required%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20type%3D%22submit%22%3ELogin%3C%2Fbutton%3E%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20type%3D%22checkbox%22%20checked%3D%22checked%22%3E%20Remember%20me%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20type%3D%22button%22%20class%3D%22cancelbtn%22%3E%20Cancel%3C%2Fbutton%3E%20%0A%20%20%20%20%20%20%20%20%20%20%20%20Forgot%20%3Ca%20href%3D%22%23%22%3E%20password%3F%20%3C%2Fa%3E%20%0A%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%20%0A%20%20%20%20%3C%2Fform%3E%20%20%20%0A%3C%2Fbody%3E%20%20%20%0A%3C%2Fhtml%3E%0A%0A%20%0A"
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user="+badUser+"&site=remark42", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "blah@user.com", emailer.to)
	assert.Contains(t, emailer.text, "Password :    blah@user.com remark42 token:")

	tknStr := strings.Split(emailer.text, " token:")[1]
	tkn, err := e.TokenService.Parse(tknStr)
	assert.NoError(t, err)
	t.Logf("%s %+v", tknStr, tkn)
	assert.Equal(t, "&lt;h1&gt; Student Login Form &lt;/h1&gt;              &lt;div&gt;             Username :                          Password :   ::blah@user.com", tkn.Handshake.ID)
	assert.Equal(t, "remark42", tkn.Audience)
	assert.True(t, tkn.ExpiresAt > tkn.NotBefore)

	assert.Equal(t, "test", e.Name())
}

func TestVerifyHandler_LoginAcceptConfirm(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedToken), http.NoBody)
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

func TestVerifyHandler_LoginAcceptConfirmWithAvatar(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		UseGravatar:  true,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedGravatar), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"grava","id":"test_47dbf92d92954b1297cae73a864c159b4d847b9f","picture":"https://www.gravatar.com/avatar/c82739de14cf64affaf30856ca95b851.jpg"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginAcceptConfirmWithGrAvatarDisabled(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		UseGravatar:  false,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedGravatar), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"grava","id":"test_47dbf92d92954b1297cae73a864c159b4d847b9f","picture":""}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginHandlerFailed(t *testing.T) {
	emailer := mockSender{}
	d := VerifyHandler{
		ProviderName: "test",
		Sender:       &emailer,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?user=myuser&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 400, rr.Code)
	assert.Equal(t, `{"error":"can't get user and address"}`+"\n", rr.Body.String())

	d.Sender = &mockSender{err: fmt.Errorf("some err")}
	handler = d.LoginHandler
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to send confirmation"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token=bad", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedBadIDToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, `{"error":"invalid handshake token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedExpired, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	d.Template = `{{.Blah}}`
	d.Sender = &mockSender{}
	handler = d.LoginHandler
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, `{"error":"can't execute confirmation template"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginHandlerAvatarFailed(t *testing.T) {
	emailer := mockSender{}
	d := VerifyHandler{
		ProviderName: "test",
		Sender:       &emailer,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:      "iss-test",
		L:           logger.Std,
		AvatarSaver: mockAvatarSaverVerif{err: fmt.Errorf("avatar save error")},
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to save avatar to proxy"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_AuthHandler(t *testing.T) {
	d := VerifyHandler{}
	handler := http.HandlerFunc(d.AuthHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/callback", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
}

func TestVerifyHandler_Logout(t *testing.T) {
	d := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", http.NoBody)
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

func (m *mockSender) Send(to, text string) error {
	if m.err != nil {
		return m.err
	}
	m.to = to
	m.text = text
	return nil
}

type mockAvatarSaverVerif struct {
	err error
	url string
}

func (a mockAvatarSaverVerif) Put(u token.User, client *http.Client) (avatarURL string, err error) {
	return a.url, a.err
}
