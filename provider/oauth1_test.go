package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/dghubble/oauth1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

const (
	timeout   = 100
	loginPort = 8983
	authPort  = 8984
)

func TestOauth1Login(t *testing.T) {
	teardown := prepOauth1Test(t, loginPort, authPort)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: timeout * time.Second}

	// check non-admin, permanent
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/login?site=remark", loginPort))
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
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
	assert.NoError(t, err)
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
	resp, err = client.Get(fmt.Sprintf("http://localhost:%d/login?site=remark", loginPort))
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	u = token.User{}
	err = json.Unmarshal(body, &u)
	assert.NoError(t, err)
	assert.Equal(t, token.User{Name: "blah", ID: "mock_myuser2", Picture: "http://example.com/ava12345.png",
		Attributes: map[string]interface{}{"admin": true}}, u)

}

func TestOauth1LoginSessionOnly(t *testing.T) {

	teardown := prepOauth1Test(t, loginPort, authPort)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: timeout * time.Second}

	// check non-admin, session
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/login?site=remark&session=1", loginPort))
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 0, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	req, err := http.NewRequest("GET", "http://example.com", http.NoBody)
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

func TestOauth1Logout(t *testing.T) {

	teardown := prepOauth1Test(t, loginPort, authPort)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: timeout * time.Second}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/logout", loginPort), http.NoBody)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 403, resp.StatusCode, "user not lagged in")

	req, err = http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/logout", loginPort), http.NoBody)
	require.NoError(t, err)
	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
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

func TestOauth1InitProvider(t *testing.T) {
	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", Issuer: "app-test"}
	provider := Oauth1Handler{name: "test"}
	res := initOauth1Handler(params, provider)
	assert.Equal(t, "cid", res.conf.ConsumerKey)
	assert.Equal(t, "csecret", res.conf.ConsumerSecret)
	assert.Equal(t, "test", res.name)
	assert.Equal(t, "app-test", res.Issuer)
}

func TestOauth1InvalidHandler(t *testing.T) {
	teardown := prepOauth1Test(t, loginPort, authPort)
	defer teardown()

	client := &http.Client{Timeout: timeout * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/login_bad", loginPort))
	require.NoError(t, err)
	assert.Equal(t, 404, resp.StatusCode)

	resp, err = client.Post(fmt.Sprintf("http://localhost:%d/login", loginPort), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}

func TestOauth1MakeRedirURL(t *testing.T) {
	cases := []struct{ rootURL, route, out string }{
		{"localhost:8080/", "/my/auth/path/google", "localhost:8080/my/auth/path/callback"},
		{"localhost:8080", "/auth/google", "localhost:8080/auth/callback"},
		{"localhost:8080/", "/auth/google", "localhost:8080/auth/callback"},
		{"localhost:8080", "/", "localhost:8080/callback"},
		{"localhost:8080/", "/", "localhost:8080/callback"},
		{"mysite.com", "", "mysite.com/callback"},
	}

	for i := range cases {
		c := cases[i]
		oh := initOauth1Handler(Params{URL: c.rootURL}, Oauth1Handler{})
		assert.Equal(t, c.out, oh.makeRedirURL(c.route))
	}
}

func prepOauth1Test(t *testing.T, loginPort, authPort int) func() { //nolint

	provider := Oauth1Handler{
		name: "mock",
		conf: oauth1.Config{
			Endpoint: oauth1.Endpoint{
				RequestTokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/request_token", authPort),
				AuthorizeURL:    fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
				AccessTokenURL:  fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
			},
		},
		infoURL: fmt.Sprintf("http://localhost:%d/user", authPort),
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "mock_" + data.Value("id"),
				Name:    data.Value("name"),
				Picture: data.Value("picture"),
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

	params := Params{URL: "url", Cid: "aFdj12348sdja", Csecret: "Dwehsq2387akss", JwtService: jwtService,
		Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: logger.Std}

	provider = initOauth1Handler(params, provider)
	svc := Service{Provider: provider}

	ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(svc.Handler)} //nolint:gosec

	count := 0
	useIds := []string{"myuser1", "myuser2"} // user for first ans second calls

	//nolint
	var (
		requestToken  = "sdjasd09AfdkzztyRadrdR"
		requestSecret = "asd34q129sjdklAJJAs"
		verifier      = "gsjad032ajjjOIU"
		accessToken   = "g0ZGZmNjVmOWI"
		accessSecret  = "qfr1239UJAkmpaf3l"
	)

	oauth := &http.Server{ //nolint:gosec
		Addr: fmt.Sprintf(":%d", authPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[MOCK OAUTH] request %s %s %+v", r.Method, r.URL, r.Header)
			switch {
			case strings.HasPrefix(r.URL.Path, "/login/oauth/request_token"):
				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				_, err := fmt.Fprintf(w, `oauth_token=%s&oauth_token_secret=%s&oauth_callback_confirmed=true`, requestToken, requestSecret)
				if err != nil {
					w.WriteHeader(500)
					return
				}
			case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
				w.Header().Add("Location", fmt.Sprintf("http://localhost:%d/callback?oauth_token=%s&oauth_verifier=%s",
					loginPort, requestToken, verifier))
				w.WriteHeader(302)
			case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				_, err := fmt.Fprintf(w, "oauth_token=%s&oauth_token_secret=%s", accessToken, accessSecret)
				if err != nil {
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(200)
			case strings.HasPrefix(r.URL.Path, "/user"):
				res := fmt.Sprintf(`{
					"id": "%s",
					"name":"blah",
					"picture":"http://exmple.com/pic1.png"
					}`, useIds[count])
				count++
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err := w.Write([]byte(res))
				assert.NoError(t, err)
			default:
				t.Fatalf("unexpected oauth request %s %s", r.Method, r.URL)
			}
		}),
	}

	go func() { _ = oauth.ListenAndServe() }()
	go func() { _ = ts.ListenAndServe() }()

	time.Sleep(time.Millisecond * 400) // let them start

	return func() {
		assert.NoError(t, ts.Close())
		assert.NoError(t, oauth.Close())
	}
}
