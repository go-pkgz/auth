package provider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

var testJwtValid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.NN7TK-IbzpNgHMtld9-7BDypMGDZdMpwCmUMSfd31Zk"

var days31 = time.Hour * 24 * 31

func TestOauth2Login(t *testing.T) {

	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, permanent
	resp, err := client.Get("http://localhost:8981/login?site=remark")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)

	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 2678400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	u := token.User{}
	err = json.Unmarshal(body, &u)
	assert.Nil(t, err)
	assert.Equal(t, token.User{Name: "blah", ID: "mock_myuser1", Picture: "http://example.com/custom.png", IP: ""}, u)

	tk := resp.Cookies()[0].Value
	jwtSvc := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})

	claims, err := jwtSvc.Parse(tk)
	require.NoError(t, err)
	t.Log(claims)
	assert.Equal(t, "remark42", claims.Issuer)
	assert.Equal(t, "remark", claims.Audience)

	// check admin user
	resp, err = client.Get("http://localhost:8981/login?site=remark")
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	u = token.User{}
	err = json.Unmarshal(body, &u)
	assert.Nil(t, err)
	assert.Equal(t, token.User{Name: "blah", ID: "mock_myuser2", Picture: "http://example.com/ava12345.png",
		Attributes: map[string]interface{}{"admin": true}}, u)
}

func TestOauth2LoginSessionOnly(t *testing.T) {

	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, session
	resp, err := client.Get("http://localhost:8981/login?site=remark&session=1")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 0, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	req, err := http.NewRequest("GET", "http://example.com", nil)
	require.Nil(t, err)

	req.AddCookie(resp.Cookies()[0])
	req.AddCookie(resp.Cookies()[1])
	req.Header.Add("X-XSRF-TOKEN", resp.Cookies()[1].Value)

	jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore)})
	res, _, err := jwtService.Get(req)
	require.Nil(t, err)
	assert.Equal(t, true, res.SessionOnly)
	t.Logf("%+v", res)
}

func TestOauth2Logout(t *testing.T) {

	teardown := prepOauth2Test(t, 8691, 8692)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", "http://localhost:8691/logout", nil)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 403, resp.StatusCode, "user not lagged in")

	req, err = http.NewRequest("GET", "http://localhost:8691/logout", nil)
	require.NoError(t, err)
	expiration := int(time.Duration(365 * 24 * time.Hour).Seconds())
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name, "token cookie cleared")
	assert.Equal(t, "", resp.Cookies()[0].Value)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name, "xsrf cookie cleared")
	assert.Equal(t, "", resp.Cookies()[1].Value)
}

func TestOauth2InitProvider(t *testing.T) {
	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", Issuer: "app-test"}
	provider := Oauth2Handler{name: "test", redirectURL: "redir"}
	res := initOauth2Handler(params, provider)
	assert.Equal(t, "cid", res.conf.ClientID)
	assert.Equal(t, "csecret", res.conf.ClientSecret)
	assert.Equal(t, "redir", res.redirectURL)
	assert.Equal(t, "test", res.name)
	assert.Equal(t, "app-test", res.Issuer)
}

func TestOauth2InvalidHandler(t *testing.T) {
	teardown := prepOauth2Test(t, 8691, 8692)
	defer teardown()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:8691/login_bad")
	require.Nil(t, err)
	assert.Equal(t, 404, resp.StatusCode)

	resp, err = client.Post("http://localhost:8691/login", "", nil)
	require.Nil(t, err)
	assert.Equal(t, 405, resp.StatusCode)
}

func prepOauth2Test(t *testing.T, loginPort, authPort int) func() {

	provider := Oauth2Handler{
		name: "mock",
		endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
			TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
		},
		redirectURL: fmt.Sprintf("http://localhost:%d/callback", loginPort),
		scopes:      []string{"user:email"},
		infoURL:     fmt.Sprintf("http://localhost:%d/user", authPort),
		mapUser: func(data userData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "mock_" + data.value("id"),
				Name:    data.value("name"),
				Picture: data.value("picture"),
			}
			return userInfo
		},
	}

	jwtService := token.NewService(token.Opts{
		SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false, TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			if claims.User != nil {
				switch claims.User.ID {
				case "mock_myuser2":
					claims.User.SetBoolAttr("admin", true)
				case "mock_myuser1":
					claims.User.Picture = "http://example.com/custom.png"
				}
			}
			return claims
		}),
	})

	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", JwtService: jwtService,
		Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: logger.Std}

	provider = initOauth2Handler(params, provider)
	svc := Service{Provider: provider}

	ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(svc.Handler)}

	count := 0
	useIds := []string{"myuser1", "myuser2"} // user for first ans second calls

	oauth := &http.Server{
		Addr: fmt.Sprintf(":%d", authPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[MOCK OAUTH] request %s %s %+v", r.Method, r.URL, r.Header)
			switch {
			case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
				state := r.URL.Query().Get("state")
				w.Header().Add("Location", fmt.Sprintf("http://localhost:%d/callback?code=g0ZGZmNjVmOWI&state=%s",
					loginPort, state))
				w.WriteHeader(302)
			case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
				res := `{
					"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
					"token_type":"bearer",
					"expires_in":3600,
					"refresh_token":"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
					"scope":"create",
					"state":"12345678"
					}`
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(200)
				_, err := w.Write([]byte(res))
				assert.NoError(t, err)
			case strings.HasPrefix(r.URL.Path, "/user"):
				res := fmt.Sprintf(`{
					"id": "%s",
					"name":"blah",
					"picture":"http://exmple.com/pic1.png"
					}`, useIds[count])
				count++
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(200)
				_, err := w.Write([]byte(res))
				assert.NoError(t, err)
			default:
				t.Fatalf("unexpected oauth request %s %s", r.Method, r.URL)
			}
		}),
	}

	go func() { _ = oauth.ListenAndServe() }()
	go func() { _ = ts.ListenAndServe() }()

	time.Sleep(time.Millisecond * 100) // let them start

	return func() {
		ts.Close()
		oauth.Close()
	}
}

func mockKeyStore() (string, error) { return "12345", nil }

type mockAvatarSaver struct{}

func (m *mockAvatarSaver) Put(u token.User) (avatarURL string, err error) {
	return "http://example.com/ava12345.png", nil
}
