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

	"github.com/go-pkgz/auth/token"
)

var days31 = time.Hour * 24 * 31

func TestLogin(t *testing.T) {

	ts, ots := mockProvider(t, 8981, 8982)
	defer func() {
		ts.Close()
		ots.Close()
	}()

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
	assert.Equal(t, token.User{Name: "blah", ID: "mock_myuser1", Picture: "http://exmple.com/pic1.png", IP: ""}, u)

	tk := resp.Cookies()[0].Value
	jwtSvc := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})

	claims, err := jwtSvc.Parse(tk)
	require.NoError(t, err)
	assert.Equal(t, "go-pkgz/auth", claims.Issuer)
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
	assert.Equal(t, token.User{Name: "blah", ID: "mock_myuser2", Picture: "http://exmple.com/pic1.png",
		Attributes: map[string]interface{}{"admin": true}}, u)
}

func TestLoginSessionOnly(t *testing.T) {

	ts, ots := mockProvider(t, 8981, 8982)
	defer func() {
		ts.Close()
		ots.Close()
	}()

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

func TestLogout(t *testing.T) {

	ts, ots := mockProvider(t, 8691, 8692)
	defer func() {
		ts.Close()
		ots.Close()
	}()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost:8691/login")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, 2, len(resp.Cookies()))
	resp, err = client.Get("http://localhost:8691/logout")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name, "token cookie cleared")
	assert.Equal(t, "", resp.Cookies()[0].Value)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name, "xsrf cookie cleared")
	assert.Equal(t, "", resp.Cookies()[1].Value)
}

func TestInitProvider(t *testing.T) {
	params := Params{URL: "url", Cid: "cid", Csecret: "csecret"}
	provider := Service{Name: "test", RedirectURL: "redir"}
	res := initService(params, provider)
	assert.Equal(t, "cid", res.conf.ClientID)
	assert.Equal(t, "csecret", res.conf.ClientSecret)
	assert.Equal(t, "redir", res.RedirectURL)
	assert.Equal(t, "test", res.Name)
}

func TestInvalidHandler(t *testing.T) {
	ts, ots := mockProvider(t, 8691, 8692)
	defer func() {
		ts.Close()
		ots.Close()
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:8691/login_bad")
	require.Nil(t, err)
	assert.Equal(t, 404, resp.StatusCode)

	resp, err = client.Post("http://localhost:8691/login", "", nil)
	require.Nil(t, err)
	assert.Equal(t, 405, resp.StatusCode)
}

func mockProvider(t *testing.T, loginPort, authPort int) (*http.Server, *http.Server) {

	provider := Service{
		Name: "mock",
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
			TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
		},
		RedirectURL: fmt.Sprintf("http://localhost:%d/callback", loginPort),
		Scopes:      []string{"user:email"},
		InfoURL:     fmt.Sprintf("http://localhost:%d/user", authPort),
		MapUser: func(data userData, _ []byte) token.User {
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
			if claims.User != nil && claims.User.ID == "mock_myuser2" {
				claims.User.SetBoolAttr("admin", true)
			}
			return claims
		}),
	})
	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", JwtService: jwtService, Issuer: "remark42"}
	// AvatarProxy:  &proxy.Avatar{Store: &mockAvatarStore, RoutePath: "/v1/avatar"},
	// PermissionChecker: &mockUserPermissions{admin: "mock_myuser2", verified: "mock_myuser2", blocked: "mock_myuser1"},

	provider = initService(params, provider)

	ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(provider.Handler)}

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
	return ts, oauth
}

func mockKeyStore(aud string) (string, error) { return "12345", nil }
