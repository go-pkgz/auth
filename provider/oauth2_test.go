package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

var testJwtValid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.NN7TK-IbzpNgHMtld9-7BDypMGDZdMpwCmUMSfd31Zk"

var days31 = time.Hour * 24 * 31

type rememberLastBearerTokenHook struct {
	LastProviderName string       `json:"lastProviderName"`
	LastUser         token.User   `json:"lastUser"`
	LastToken        oauth2.Token `json:"lastToken"`
}

func (h *rememberLastBearerTokenHook) hook(s string, user token.User, o oauth2.Token) {
	h.LastProviderName = s
	h.LastUser = user
	h.LastToken = o
}

func TestOauth2Login(t *testing.T) {

	teardown := prepOauth2Test(t, 8981, 8982, nil)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, permanent
	resp, err := client.Get("http://localhost:8981/login?site=remark")
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
	resp, err = client.Get("http://localhost:8981/login?site=remark")
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	u = token.User{}
	err = json.Unmarshal(body, &u)
	assert.NoError(t, err)
	assert.Equal(t, token.User{Name: "blah", ID: "mock_myuser2", Picture: "http://example.com/ava12345.png",
		Attributes: map[string]any{"admin": true}}, u)
}

func TestOauth2LoginBearerTokenHook(t *testing.T) {

	btHook := rememberLastBearerTokenHook{}
	teardown := prepOauth2Test(t, 8981, 8982, btHook.hook)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, permanent
	resp, err := client.Get("http://localhost:8981/login?site=remark")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, "mock", btHook.LastProviderName)
	assert.Equal(t, "mock_myuser1", btHook.LastUser.ID)
	assert.Equal(t, "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3", btHook.LastToken.AccessToken)

	// check admin user
	resp, err = client.Get("http://localhost:8981/login?site=remark")
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, "mock", btHook.LastProviderName)
	assert.Equal(t, "mock_myuser2", btHook.LastUser.ID)
	assert.Equal(t, "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3", btHook.LastToken.AccessToken)
}

func TestOauth2LoginSessionOnly(t *testing.T) {

	teardown := prepOauth2Test(t, 8981, 8982, nil)
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

func TestOauth2LoginNoAva(t *testing.T) {

	teardown := prepOauth2Test(t, 8981, 8982, nil)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, session
	resp, err := client.Get("http://localhost:8981/login?site=remark&noava=1")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.NotEqual(t, 0, resp.Cookies()[0].MaxAge)
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
	assert.Equal(t, "http://example.com/fake.png", res.User.Picture)
	assert.Equal(t, true, res.NoAva)
	t.Logf("%+v", res)
}

func TestOauth2Logout(t *testing.T) {

	teardown := prepOauth2Test(t, 8691, 8692, nil)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", "http://localhost:8691/logout", http.NoBody)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 403, resp.StatusCode, "user not lagged in")

	req, err = http.NewRequest("GET", "http://localhost:8691/logout", http.NoBody)
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

func TestOauth2InitProvider(t *testing.T) {
	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", Issuer: "app-test"}
	provider := Oauth2Handler{name: "test"}
	res := initOauth2Handler(params, provider)
	assert.Equal(t, "cid", res.conf.ClientID)
	assert.Equal(t, "csecret", res.conf.ClientSecret)
	assert.Equal(t, "test", res.name)
	assert.Equal(t, "app-test", res.Issuer)
}

func TestOauth2InvalidHandler(t *testing.T) {
	teardown := prepOauth2Test(t, 8691, 8692, nil)
	defer teardown()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:8691/login_bad")
	require.Nil(t, err)
	assert.Equal(t, 404, resp.StatusCode)

	resp, err = client.Post("http://localhost:8691/login", "", nil)
	require.Nil(t, err)
	assert.Equal(t, 500, resp.StatusCode)
}

func TestOauth2AuthHandlerReadsHandshakeFromCookieOnly(t *testing.T) {
	teardown := prepOauth2Test(t, 8971, 8972, nil)
	defer teardown()

	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	startLogin := func(t *testing.T) (callbackURL, handshake string) {
		t.Helper()
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		client := &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: noRedirect}
		resp, err := client.Get("http://localhost:8971/login?site=remark")
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusFound, resp.StatusCode)
		for _, c := range resp.Cookies() {
			if c.Name == "JWT" {
				handshake = c.Value
			}
		}
		require.NotEmpty(t, handshake)
		resp, err = client.Get(resp.Header.Get("Location"))
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusFound, resp.StatusCode)
		return resp.Header.Get("Location"), handshake
	}

	tbl := []struct {
		name string
		req  func(callbackURL, handshake string) *http.Request
	}{
		{name: "query", req: func(callbackURL, handshake string) *http.Request {
			r, err := http.NewRequest(http.MethodGet, callbackURL+"&token="+url.QueryEscape(handshake), http.NoBody)
			require.NoError(t, err)
			return r
		}},
		{name: "header", req: func(callbackURL, handshake string) *http.Request {
			r, err := http.NewRequest(http.MethodGet, callbackURL, http.NoBody)
			require.NoError(t, err)
			r.Header.Set("X-JWT", handshake)
			return r
		}},
	}
	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			callbackURL, handshake := startLogin(t)
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(tt.req(callbackURL, handshake))
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			for _, c := range resp.Cookies() {
				assert.NotEqual(t, "JWT", c.Name, "no session cookie for a handshake outside the cookie")
			}
		})
	}
}

// TestOauth2LoginFromRejectsExternalHost reproduces the open-redirect attack
// against the oauth2 login flow.
//
// Attack scenario (before this fix):
//
//  1. Attacker crafts a link to the legitimate site:
//     https://comments.example.com/auth/github/login?from=https://evil.example.com/phish
//  2. Victim clicks the link, sees the real GitHub OAuth consent screen and approves.
//  3. After the OAuth dance completes, the AuthHandler executed
//     `http.Redirect(w, r, oauthClaims.Handshake.From, ...)`
//     with no validation on `From` — so the browser was bounced straight to
//     https://evil.example.com/phish, carrying a fresh session cookie and the
//     trust the user had in the legitimate brand.
//
// With the fix in place and host validation enabled (Opts.AllowedRedirectHosts
// non-nil), `from` must point at the service's own host or a host listed in
// the allowlist. Otherwise the handler renders the user-info JSON and logs a
// [WARN]. Same vector applies to oauth1, apple and verify providers — they
// all share the same redirect-from-handshake pattern.
func TestOauth2LoginFromRejectsExternalHost(t *testing.T) {
	enablePolicy := func(p *Params) {
		p.AllowedRedirectHosts = token.AllowedHostsFunc(func() ([]string, error) { return nil, nil })
	}
	teardown := prepOauth2Test(t, 8981, 8982, nil, enablePolicy)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := &http.Client{Jar: jar, Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !strings.HasPrefix(req.URL.Host, "localhost") {
				return fmt.Errorf("blocked external redirect to %s", req.URL)
			}
			return nil
		},
	}

	resp, err := client.Get("http://localhost:8981/login?site=remark&from=https://evil.example.com/phish")
	require.NoError(t, err, "no external redirect expected — fix should reject evil host")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"name":"blah"`, "must return user JSON, not redirect to evil")
	assert.NotContains(t, string(body), "evil.example.com")
}

func TestOauth2LoginFromAllowsAllowlistedHost(t *testing.T) {
	enablePolicy := func(p *Params) {
		p.AllowedRedirectHosts = token.AllowedHostsFunc(func() ([]string, error) { return []string{"trusted.example.com"}, nil })
	}
	teardown := prepOauth2Test(t, 8985, 8986, nil, enablePolicy)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	var lastRedirect string
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			lastRedirect = req.URL.String()
			if strings.Contains(req.URL.Host, "trusted.example.com") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get("http://localhost:8985/login?site=remark&from=https://trusted.example.com/back")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "must 303-redirect to trusted host")
	assert.Equal(t, "https://trusted.example.com/back", resp.Header.Get("Location"))
	assert.Contains(t, lastRedirect, "trusted.example.com")
}

func TestOauth2LoginDoesNotLogUserProfile(t *testing.T) {
	var logMu sync.Mutex
	logBuf := strings.Builder{}
	captureLog := func(p *Params) {
		p.L = logger.Func(func(format string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			fmt.Fprintf(&logBuf, format, args...)
		})
	}
	teardown := prepOauth2Test(t, 8991, 8992, nil, captureLog)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost:8991/login?site=remark")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	logged := func() string {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.String()
	}()
	assert.Contains(t, logged, "got raw user info keys=[email id name picture]")
	assert.Contains(t, logged, `user info id="mock_myuser1" name="blah" picture=true`)
	assert.NotContains(t, logged, "oauth-sensitive@example.com")
}

func TestOauth2LoginSendsPKCEChallenge(t *testing.T) {
	jwtSvc := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})
	var logBuf strings.Builder
	var logMu sync.Mutex
	captureLog := logger.Func(func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Fprintf(&logBuf, format+"\n", args...)
	})
	p := initOauth2Handler(Params{URL: "http://example.com", Cid: "cid", Csecret: "csecret", JwtService: jwtSvc,
		Issuer: "remark42", L: captureLog},
		Oauth2Handler{name: "mock", endpoint: oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize",
			TokenURL: "https://idp.example.com/token"}})

	login := func() (challenge, verifier string) {
		rr := httptest.NewRecorder()
		p.LoginHandler(rr, httptest.NewRequest(http.MethodGet, "/auth/mock/login?site=remark", http.NoBody))
		require.Equal(t, http.StatusFound, rr.Code)
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "S256", loc.Query().Get("code_challenge_method"))
		challenge = loc.Query().Get("code_challenge")
		require.NotEmpty(t, challenge, "authorize URL must carry a PKCE challenge")

		var jwtCookie *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == "JWT" {
				jwtCookie = c
			}
		}
		require.NotNil(t, jwtCookie, "handshake cookie must be set")
		claims, err := jwtSvc.Parse(jwtCookie.Value)
		require.NoError(t, err)
		require.NotNil(t, claims.Handshake)
		verifier = claims.Handshake.CodeVerifier
		require.NotEmpty(t, verifier, "handshake must keep the verifier for the callback")
		assert.Equal(t, challenge, oauth2.S256ChallengeFromVerifier(verifier), "challenge must be derived from the stored verifier")
		return challenge, verifier
	}

	c1, v1 := login()
	c2, v2 := login()
	assert.NotEqual(t, v1, v2, "each login needs a fresh verifier")
	assert.NotEqual(t, c1, c2)

	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	assert.Contains(t, logged, "login url", "the debug line must still be written")
	assert.NotContains(t, logged, v1, "the verifier must never be logged")
	assert.NotContains(t, logged, v2, "the verifier must never be logged")
}

func TestOauth2CallbackWithoutPKCEVerifier(t *testing.T) {
	// a login started before PKCE support has no verifier in its handshake; the callback must not send one
	teardown := prepOauth2Test(t, 8695, 8696, nil)
	defer teardown()

	jwtSvc := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})
	hs, err := jwtSvc.Token(token.Claims{
		Handshake:    &token.Handshake{State: "pre-pkce-state"},
		AuthProvider: &token.AuthProvider{Name: "mock"},
		StandardClaims: jwt.StandardClaims{
			Id:        "cid",
			Audience:  "remark",
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
		},
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8695/callback?code=g0ZGZmNjVmOWI&state=pre-pkce-state", http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: hs})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "callback must succeed without a verifier, got %s", string(body))
}

func TestMakeRedirURL(t *testing.T) {
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
		oh := initOauth2Handler(Params{URL: c.rootURL}, Oauth2Handler{})
		assert.Equal(t, c.out, oh.makeRedirURL(c.route))
	}
}

func TestOauth2LoginRejectsFailedUserInfo(t *testing.T) {
	tbl := []struct {
		name     string
		status   int
		body     string
		wantCode int
		wantLog  string
	}{
		// revoked token, rate limit or outage: valid json, no identity fields, mapping it would sign
		// everyone in under the same empty-value id
		{name: "non-2xx response", status: http.StatusUnauthorized, body: `{"message":"Bad credentials"}`,
			wantCode: http.StatusServiceUnavailable, wantLog: "status 401 Unauthorized"},
		// a login failed on unparsable user info must log the parse error as its cause
		{name: "2xx response with non-json body", status: http.StatusOK, body: `<html>rate limited</html>`,
			wantCode: http.StatusInternalServerError, wantLog: "invalid character '<'"},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			loginPort, authPort := 8995, 8996
			prov := Oauth2Handler{
				name: "mock",
				endpoint: oauth2.Endpoint{
					AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
					TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
				},
				scopes:  []string{"user:email"},
				infoURL: fmt.Sprintf("http://localhost:%d/user", authPort),
				mapUser: func(data UserData, _ []byte) token.User {
					return token.User{ID: "mock_" + data.Value("id"), Name: data.Value("name")}
				},
			}

			var logMu sync.Mutex
			logBuf := strings.Builder{}
			captureLog := logger.Func(func(format string, args ...any) {
				logMu.Lock()
				defer logMu.Unlock()
				fmt.Fprintf(&logBuf, format, args...)
			})

			jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
				TokenDuration: time.Hour, CookieDuration: days31})
			prov = initOauth2Handler(Params{URL: "url", Cid: "cid", Csecret: "csecret", JwtService: jwtService,
				Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: captureLog}, prov)
			svc := Service{Provider: prov}

			ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(svc.Handler)} //nolint:gosec
			oauth := &http.Server{                                                                          //nolint:gosec
				Addr: fmt.Sprintf(":%d", authPort),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
						w.Header().Add("Location", fmt.Sprintf("http://localhost:%d/callback?code=g0ZGZmNjVmOWI&state=%s",
							loginPort, r.URL.Query().Get("state")))
						w.WriteHeader(302)
					case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
						w.Header().Set("Content-Type", "application/json; charset=utf-8")
						_, err := w.Write([]byte(`{"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3","token_type":"bearer"}`))
						assert.NoError(t, err)
					case strings.HasPrefix(r.URL.Path, "/user"):
						w.WriteHeader(tt.status)
						_, err := w.Write([]byte(tt.body))
						assert.NoError(t, err)
					default:
						t.Fatalf("unexpected oauth request %s %s", r.Method, r.URL)
					}
				}),
			}

			startServer(t, oauth)
			startServer(t, ts)
			defer func() {
				assert.NoError(t, ts.Close())
				assert.NoError(t, oauth.Close())
			}()

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

			resp, err := client.Get(fmt.Sprintf("http://localhost:%d/login?site=remark", loginPort))
			require.NoError(t, err)
			defer func() { assert.NoError(t, resp.Body.Close()) }()
			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantCode, resp.StatusCode, "login must fail, got body %s", string(body))
			assert.NotContains(t, string(body), "mock_", "no user may be mapped from a failed user info response")
			assert.Empty(t, resp.Cookies(), "no auth cookie on failed login")
			logMu.Lock()
			defer logMu.Unlock()
			assert.Contains(t, logBuf.String(), tt.wantLog)
		})
	}
}

func TestOauth2LoginRejectsEmptyUserID(t *testing.T) {
	// a user mapped without an id would be the same user for everyone mapped that way
	login := httptest.NewUnstartedServer(nil)
	defer login.Close()
	loginURL := "http://" + login.Listener.Addr().String()

	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
			http.Redirect(w, r, loginURL+"/callback?code=g0ZGZmNjVmOWI&state="+url.QueryEscape(r.URL.Query().Get("state")),
				http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, err := w.Write([]byte(`{"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3","token_type":"bearer"}`))
			assert.NoError(t, err)
		case strings.HasPrefix(r.URL.Path, "/user"):
			// a successful answer with a name and no identity field
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, err := w.Write([]byte(`{"name":"blah"}`))
			assert.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer oauth.Close()

	prov := Oauth2Handler{
		name: "mock",
		endpoint: oauth2.Endpoint{
			AuthURL:  oauth.URL + "/login/oauth/authorize",
			TokenURL: oauth.URL + "/login/oauth/access_token",
		},
		infoURL: oauth.URL + "/user",
		mapUser: func(data UserData, _ []byte) token.User {
			return token.User{ID: data.Value("id"), Name: data.Value("name")}
		},
	}
	jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})
	prov = initOauth2Handler(Params{URL: loginURL, Cid: "cid", Csecret: "csecret", JwtService: jwtService,
		Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: logger.Std}, prov)
	login.Config.Handler = http.HandlerFunc(Service{Provider: prov}.Handler)
	login.Start()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get(loginURL + "/login?site=remark")
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "login must fail, got body %s", string(body))
	assert.NotContains(t, string(body), "blah", "no user may be mapped without an id")
	assert.Empty(t, resp.Cookies(), "no auth cookie on failed login")
}

func prepOauth2Test(t *testing.T, loginPort, authPort int, btHook BearerTokenHook, paramOpts ...func(*Params)) func() {

	provider := Oauth2Handler{
		name: "mock",
		endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
			TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
		},
		scopes:  []string{"user:email"},
		infoURL: fmt.Sprintf("http://localhost:%d/user", authPort),
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "mock_" + data.Value("id"),
				Name:    data.Value("name"),
				Picture: data.Value("picture"),
			}
			return userInfo
		},
		bearerTokenHook: btHook,
	}

	jwtService := token.NewService(token.Opts{
		SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false, TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			if claims.User != nil {
				switch claims.User.ID {
				case "mock_myuser2":
					claims.User.SetBoolAttr("admin", true)
				case "mock_myuser1":
					if !claims.NoAva {
						claims.User.Picture = "http://example.com/custom.png"
					}
				}
			}
			return claims
		}),
	})

	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", JwtService: jwtService,
		Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: logger.Std}

	for _, opt := range paramOpts {
		opt(&params)
	}

	provider = initOauth2Handler(params, provider)
	svc := Service{Provider: provider}

	ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(svc.Handler)} //nolint:gosec

	count := 0
	useIDs := []string{"myuser1", "myuser2"} // user for first ans second calls

	var pkceMu sync.Mutex
	var challenge, challengeMethod string // recorded by the authorize endpoint, checked by the token endpoint

	oauth := &http.Server{ //nolint:gosec
		Addr: fmt.Sprintf(":%d", authPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[MOCK OAUTH] request %s %s %+v", r.Method, r.URL, r.Header)
			switch {
			case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
				pkceMu.Lock()
				challenge, challengeMethod = r.URL.Query().Get("code_challenge"), r.URL.Query().Get("code_challenge_method")
				pkceMu.Unlock()
				state := r.URL.Query().Get("state")
				w.Header().Add("Location", fmt.Sprintf("http://localhost:%d/callback?code=g0ZGZmNjVmOWI&state=%s",
					loginPort, state))
				w.WriteHeader(302)
			case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
				// behave as a server enforcing PKCE: a challenge requires the matching verifier,
				// and no challenge means no verifier is expected
				require.NoError(t, r.ParseForm())
				verifier := r.PostForm.Get("code_verifier")
				pkceMu.Lock()
				wantChallenge, method := challenge, challengeMethod
				pkceMu.Unlock()
				_, sent := r.PostForm["code_verifier"]
				pkceOK := !sent && wantChallenge == ""
				if wantChallenge != "" {
					pkceOK = method == "S256" && oauth2.S256ChallengeFromVerifier(verifier) == wantChallenge
				}
				if !pkceOK {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
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
					"email":"oauth-sensitive@example.com",
					"picture":"http://exmple.com/pic1.png"
					}`, useIDs[count])
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

	startServer(t, oauth)
	startServer(t, ts)

	return func() {
		assert.NoError(t, ts.Close())
		assert.NoError(t, oauth.Close())
	}
}

func mockKeyStore(string) (string, error) { return "12345", nil }

type mockAvatarSaver struct{}

func (m *mockAvatarSaver) Put(u token.User, _ *http.Client) (avatarURL string, err error) {
	if u.Picture != "" {
		return "http://example.com/ava12345.png", nil
	}
	return "http://example.com/fake.png", nil

}

// PutContent satisfies the avatarContentSaver type assertion in telegram.go so
// the test mock behaves like avatar.Proxy and the bot-token-aware path can be
// exercised. The body is drained but the saver returns the same canned URL it
// would for a regular Put, so existing tests asserting on Picture stay valid.
func (m *mockAvatarSaver) PutContent(_ string, content io.Reader) (avatarURL string, err error) {
	if _, e := io.Copy(io.Discard, content); e != nil {
		return "", e
	}
	return "http://example.com/ava12345.png", nil
}

func TestOauth2AvatarFetchSendsTokenOnlyToInfoHost(t *testing.T) {
	const accessToken = "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
	cases := []struct {
		name    string
		picture func(infoHost, otherHost string) string
		want    map[string][]string
	}{
		{name: "picture on another host",
			picture: func(_, other string) string { return other + "/pic" },
			want:    map[string][]string{"other /pic": {""}}},
		{name: "picture on the user info host",
			picture: func(info, _ string) string { return info + "/photo" },
			want:    map[string][]string{"info /photo": {"Bearer " + accessToken}}},
		{name: "user info host redirects the picture to another host",
			picture: func(info, _ string) string { return info + "/moved" },
			want:    map[string][]string{"info /moved": {"Bearer " + accessToken}, "other /pic": {""}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string][]string{}
			record := func(server string, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				key := server + " " + r.URL.Path
				seen[key] = append(seen[key], r.Header.Get("Authorization"))
			}

			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				record("other", r)
				_, err := w.Write([]byte("picture"))
				assert.NoError(t, err)
			}))
			defer other.Close()

			login := httptest.NewUnstartedServer(nil)
			defer login.Close()
			loginURL := "http://" + login.Listener.Addr().String()

			var infoURL string
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login/oauth/authorize":
					http.Redirect(w, r, loginURL+"/callback?code=g0ZGZmNjVmOWI&state="+url.QueryEscape(r.URL.Query().Get("state")),
						http.StatusFound)
				case "/login/oauth/access_token":
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, err := fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer"}`, accessToken)
					assert.NoError(t, err)
				case "/user":
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, err := fmt.Fprintf(w, `{"id":"myuser1","name":"blah","picture":%q}`, c.picture(infoURL, other.URL))
					assert.NoError(t, err)
				case "/photo":
					record("info", r)
					_, err := w.Write([]byte("picture"))
					assert.NoError(t, err)
				case "/moved":
					record("info", r)
					http.Redirect(w, r, other.URL+"/pic", http.StatusFound)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer oauth.Close()
			infoURL = oauth.URL

			prov := Oauth2Handler{
				name: "mock",
				endpoint: oauth2.Endpoint{
					AuthURL:  oauth.URL + "/login/oauth/authorize",
					TokenURL: oauth.URL + "/login/oauth/access_token",
				},
				infoURL: oauth.URL + "/user",
				mapUser: func(data UserData, _ []byte) token.User {
					return token.User{ID: "mock_" + data.Value("id"), Name: data.Value("name"), Picture: data.Value("picture")}
				},
			}
			jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
				TokenDuration: time.Hour, CookieDuration: days31})
			prov = initOauth2Handler(Params{URL: loginURL, Cid: "cid", Csecret: "csecret", JwtService: jwtService,
				Issuer: "remark42", AvatarSaver: fetchingAvatarSaver{}, L: logger.Std}, prov)
			login.Config.Handler = http.HandlerFunc(Service{Provider: prov}.Handler)
			login.Start()

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
			resp, err := client.Get(loginURL + "/login?site=remark")
			require.NoError(t, err)
			defer func() { assert.NoError(t, resp.Body.Close()) }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, "login must succeed, got body %s", string(body))

			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, c.want, seen)
		})
	}
}

func TestOauth2InfoRequestRedirect(t *testing.T) {
	const accessToken = "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
	cases := []struct {
		name       string
		infoPath   string
		wantStatus int
		wantOther  []string
	}{
		{name: "redirect to another origin is refused", infoPath: "/to-other", wantStatus: http.StatusServiceUnavailable},
		{name: "redirect within the origin is followed", infoPath: "/to-same", wantStatus: http.StatusOK},
		{name: "redirect past the hop cap is refused", infoPath: "/loop?n=0", wantStatus: http.StatusServiceUnavailable},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			var otherAuth []string
			userJSON := `{"id":"myuser1","name":"blah"}`

			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				otherAuth = append(otherAuth, r.Header.Get("Authorization"))
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err := w.Write([]byte(userJSON))
				assert.NoError(t, err)
			}))
			defer other.Close()

			login := httptest.NewUnstartedServer(nil)
			defer login.Close()
			loginURL := "http://" + login.Listener.Addr().String()

			var sameAuth string
			var oauthURL string
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login/oauth/authorize":
					http.Redirect(w, r, loginURL+"/callback?code=g0ZGZmNjVmOWI&state="+url.QueryEscape(r.URL.Query().Get("state")),
						http.StatusFound)
				case "/login/oauth/access_token":
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, err := fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer"}`, accessToken)
					assert.NoError(t, err)
				case "/to-other":
					http.Redirect(w, r, other.URL+"/user?sig=s3cr3tsig", http.StatusFound)
				case "/loop":
					n, err := strconv.Atoi(r.URL.Query().Get("n"))
					require.NoError(t, err)
					if n < 9 {
						http.Redirect(w, r, fmt.Sprintf("%s/loop?n=%d", oauthURL, n+1), http.StatusFound)
						return
					}
					http.Redirect(w, r, oauthURL+"/user?sig=s3cr3tsig", http.StatusFound)
				case "/to-same":
					http.Redirect(w, r, oauthURL+"/user", http.StatusFound)
				case "/user":
					mu.Lock()
					sameAuth = r.Header.Get("Authorization")
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, err := w.Write([]byte(userJSON))
					assert.NoError(t, err)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer oauth.Close()
			oauthURL = oauth.URL

			prov := Oauth2Handler{
				name: "mock",
				endpoint: oauth2.Endpoint{
					AuthURL:  oauth.URL + "/login/oauth/authorize",
					TokenURL: oauth.URL + "/login/oauth/access_token",
				},
				infoURL: oauth.URL + c.infoPath,
				mapUser: func(data UserData, _ []byte) token.User {
					return token.User{ID: "mock_" + data.Value("id"), Name: data.Value("name")}
				},
			}
			var logs strings.Builder
			lg := logger.Func(func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				logs.WriteString(fmt.Sprintf(format, args...) + "\n")
			})
			jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
				TokenDuration: time.Hour, CookieDuration: days31})
			prov = initOauth2Handler(Params{URL: loginURL, Cid: "cid", Csecret: "csecret", JwtService: jwtService,
				Issuer: "remark42", L: lg}, prov)
			login.Config.Handler = http.HandlerFunc(Service{Provider: prov}.Handler)
			login.Start()

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
			resp, err := client.Get(loginURL + "/login?site=remark")
			require.NoError(t, err)
			defer func() { assert.NoError(t, resp.Body.Close()) }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, c.wantStatus, resp.StatusCode, "body %s", string(body))
			assert.NotContains(t, string(body), "s3cr3tsig")

			mu.Lock()
			defer mu.Unlock()
			assert.NotContains(t, logs.String(), "s3cr3tsig")
			assert.Equal(t, c.wantOther, otherAuth)
			if c.wantStatus != http.StatusOK {
				assert.Empty(t, sameAuth, "the info url's own /user is never requested")
				return
			}
			assert.Equal(t, "Bearer "+accessToken, sameAuth)
		})
	}
}

func TestOauth2InfoClientRedirectPolicy(t *testing.T) {
	first := mustParseURL(t, "https://api.example.com/user")
	req := func(raw string) *http.Request { return &http.Request{URL: mustParseURL(t, raw)} }
	via := []*http.Request{{URL: first}}
	tooMany := make([]*http.Request, 10)
	for i := range tooMany {
		tooMany[i] = &http.Request{URL: first}
	}
	var hookCalled bool
	rewrite := func(r *http.Request, _ []*http.Request) error {
		hookCalled = true
		r.URL = mustParseURL(t, "https://evil.example.com/user")
		return nil
	}
	moveFirst := func(_ *http.Request, v []*http.Request) error {
		hookCalled = true
		v[0].URL = mustParseURL(t, "https://evil.example.com/user")
		return nil
	}
	errHook := errors.New("hook refused")
	cases := []struct {
		name     string
		infoURL  string
		hook     func(*http.Request, []*http.Request) error
		next     *http.Request
		via      []*http.Request
		wantErr  error
		wantHook bool
	}{
		{name: "same origin", next: req("https://API.example.com:443/v2/user"), via: via},
		{name: "another host", next: req("https://evil.example.com/user"), via: via, wantErr: http.ErrUseLastResponse},
		{name: "another scheme", next: req("http://api.example.com/user"), via: via, wantErr: http.ErrUseLastResponse},
		{name: "non-ascii info host", infoURL: "https://äpi.example.com/user", next: req("https://äpi.example.com/me"),
			via: via, wantErr: http.ErrUseLastResponse},
		{name: "default cap", next: req("https://api.example.com/user"), via: tooMany, wantErr: http.ErrUseLastResponse},
		{name: "hook error kept", hook: func(*http.Request, []*http.Request) error { return errHook },
			next: req("https://api.example.com/user"), via: via, wantErr: errHook},
		{name: "hook replaces the cap", hook: func(*http.Request, []*http.Request) error { return nil },
			next: req("https://api.example.com/user"), via: tooMany},
		{name: "origin checked after hook rewrite", hook: rewrite, next: req("https://api.example.com/user"), via: via,
			wantErr: http.ErrUseLastResponse, wantHook: true},
		{name: "origin from the info url, not from via", hook: moveFirst, next: req("https://evil.example.com/user"),
			via: []*http.Request{{URL: first}}, wantErr: http.ErrUseLastResponse, wantHook: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hookCalled = false
			infoURL := c.infoURL
			if infoURL == "" {
				infoURL = first.String()
			}
			ic := Oauth2Handler{infoURL: infoURL}.infoClient(&http.Client{CheckRedirect: c.hook})
			err := ic.CheckRedirect(c.next, c.via)
			assert.True(t, err == c.wantErr, "got %v, want %v", err, c.wantErr)
			assert.Equal(t, c.wantHook, hookCalled)
		})
	}

	authed := &http.Client{}
	Oauth2Handler{}.infoClient(authed)
	assert.Nil(t, authed.CheckRedirect, "the oauth2 client itself keeps its redirect policy")
}

func TestURLOrigin(t *testing.T) {
	cases := []struct{ a, b string }{
		{"https://graph.microsoft.com/v1.0/me", "https://GRAPH.microsoft.com:443/beta/me/photo/$value"},
		{"http://127.0.0.1/user", "http://127.0.0.1:80/photo"},
	}
	for _, c := range cases {
		a, b := mustParseURL(t, c.a), mustParseURL(t, c.b)
		assert.Equal(t, urlOrigin(a), urlOrigin(b), "%s and %s", c.a, c.b)
	}

	differ := []struct{ a, b string }{
		{"https://graph.microsoft.com/v1.0/me", "http://graph.microsoft.com/beta/me/photo/$value"},
		{"https://graph.microsoft.com/v1.0/me", "https://graph.microsoft.com:8443/photo"},
		{"https://api.github.com/user", "https://avatars.githubusercontent.com/u/1"},
		{"https://example.com/user", "https://pics.example.com/u/1"},
	}
	for _, c := range differ {
		a, b := mustParseURL(t, c.a), mustParseURL(t, c.b)
		assert.NotEqual(t, urlOrigin(a), urlOrigin(b), "%s and %s", c.a, c.b)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

type fetchingAvatarSaver struct{}

func (fetchingAvatarSaver) Put(u token.User, client *http.Client) (avatarURL string, err error) {
	resp, err := client.Get(u.Picture)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("picture status %s", resp.Status)
	}
	return "http://example.com/ava12345.png", nil
}

func TestOauth2AvatarClientTransport(t *testing.T) {
	errRedirect := errors.New("redirect policy of the oauth2 client")
	cases := []struct {
		name    string
		infoURL string
		want    map[string]string
	}{
		{name: "token only for the info origin", infoURL: "https://graph.microsoft.com/v1.0/me",
			want: map[string]string{
				"https://graph.microsoft.com/beta/me/photo/$value":   "Bearer tok",
				"https://GRAPH.microsoft.com:443/beta/me/photo":      "Bearer tok",
				"https://graph.mİcrosoft.com/beta/me/photo":          "",
				"http://graph.microsoft.com/beta/me/photo/$value":    "",
				"https://avatars.githubusercontent.com/u/1?v=4":      "",
				"https://graph.microsoft.com.example.com/photo.jpeg": "",
			}},
		{name: "no token for any picture with a non-ascii info host", infoURL: "https://gräph.example.com/me",
			want: map[string]string{
				"https://gräph.example.com/photo":        "",
				"https://xn--grph-koa.example.com/photo": "",
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := map[string]string{}
			base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				got[r.URL.String()] = r.Header.Get("Authorization")
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			authed := &http.Client{
				Transport:     &oauth2.Transport{Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), Base: base},
				CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
			}
			client := Oauth2Handler{infoURL: c.infoURL}.avatarClient(authed)
			want := map[string]string{}
			for picture, header := range c.want {
				req, err := http.NewRequest(http.MethodGet, picture, http.NoBody)
				require.NoError(t, err)
				resp, err := client.Transport.RoundTrip(req)
				require.NoError(t, err, "every request goes through the base transport of the oauth2 client")
				require.NoError(t, resp.Body.Close())
				want[req.URL.String()] = header
			}
			assert.Equal(t, want, got)
			require.NotNil(t, client.CheckRedirect)
			assert.ErrorIs(t, client.CheckRedirect(nil, nil), errRedirect)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
