package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/v2/logger"
	"github.com/go-pkgz/auth/v2/token"
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
	assert.Equal(t, "remark", claims.Audience[0])

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
// The `from` value is signed into the handshake JWT, so it cannot be tampered
// mid-flow — but the *initial* link is attacker-controlled and any URL fits
// in the JWT. This is a textbook unvalidated-redirect / OAuth-flow phishing
// vector applicable to oauth1, oauth2, apple and verify providers (they all
// share the same redirect-from-handshake pattern).
//
// With the fix in place and host validation enabled (Opts.AllowedRedirectHosts
// non-nil), `from` must point at the service's own host or a host listed in
// the allowlist. Otherwise the handler renders the user-info JSON and logs a
// [WARN]. This test enables the policy via `enablePolicy` (a getter that
// returns an empty slice, which restricts redirects to the service URL host
// only — here "url"), so any real external host is refused. The default (nil)
// allowlist is permissive by design and is covered separately by the
// validator unit tests in redirect_test.go.
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
				return http.ErrUseLastResponse // stop here, capture the redirect
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
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "cid",
			Audience:  []string{"remark"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
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

func TestTwitterV2Login(t *testing.T) {
	cases := []struct {
		name        string
		rejectToken bool   // the token endpoint refuses the exchange
		userInfo    string // the user object of the account when empty
		wantStatus  int
	}{
		{name: "signs in", wantStatus: http.StatusOK},
		{name: "rejected exchange is not repeated with the secret in the body", rejectToken: true,
			wantStatus: http.StatusInternalServerError},
		{name: "answer without user object",
			userInfo:   `{"errors":[{"title":"Forbidden","type":"about:blank","status":403}]}`,
			wantStatus: http.StatusServiceUnavailable},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const code, accessToken = "g0ZGZmNjVmOWI", "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"

			login := httptest.NewUnstartedServer(nil)
			defer login.Close()
			loginURL := "http://" + login.Listener.Addr().String()

			var mu sync.Mutex
			var challenge string
			var exchanges int
			var secretInBody bool
			refuse := func(w http.ResponseWriter, status int, oauthErr string) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, err := fmt.Fprintf(w, `{"error":%q}`, oauthErr)
				assert.NoError(t, err)
			}

			// the mock keeps to what X documents: pkce with S256, a confidential client known by the basic
			// header only, a bearer token for the lookup, the user under "data"
			x := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/i/oauth2/authorize":
					q := r.URL.Query()
					scopes := strings.Fields(q.Get("scope"))
					if q.Get("response_type") != "code" || q.Get("client_id") != "cid" || q.Get("state") == "" ||
						q.Get("redirect_uri") != loginURL+"/callback" || q.Get("code_challenge") == "" ||
						q.Get("code_challenge_method") != "S256" ||
						!slices.Contains(scopes, "users.read") || !slices.Contains(scopes, "tweet.read") {
						refuse(w, http.StatusBadRequest, "invalid_request")
						return
					}
					mu.Lock()
					challenge = q.Get("code_challenge")
					mu.Unlock()
					http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
				case "/2/oauth2/token":
					if !assert.NoError(t, r.ParseForm()) {
						return
					}
					mu.Lock()
					exchanges++
					secretInBody = secretInBody || r.PostForm.Has("client_secret")
					wantChallenge := challenge
					mu.Unlock()
					if id, secret, ok := r.BasicAuth(); !ok || id != "cid" || secret != "csecret" {
						refuse(w, http.StatusUnauthorized, "unauthorized_client")
						return
					}
					f := r.PostForm
					if c.rejectToken || f.Get("grant_type") != "authorization_code" || f.Get("code") != code ||
						f.Get("redirect_uri") != loginURL+"/callback" ||
						oauth2.S256ChallengeFromVerifier(f.Get("code_verifier")) != wantChallenge {
						refuse(w, http.StatusBadRequest, "invalid_request")
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, err := fmt.Fprintf(w, `{"token_type":"bearer","expires_in":7200,"access_token":%q,"scope":"users.read tweet.read"}`,
						accessToken)
					assert.NoError(t, err)
				case "/2/users/me":
					if r.Header.Get("Authorization") != "Bearer "+accessToken {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					body := c.userInfo
					if body == "" {
						body = `{"data":{"id":"2244994945","name":"Jane Reader","username":"janereader"}}`
						// the picture is not among the default fields
						if strings.Contains(r.URL.Query().Get("user.fields"), "profile_image_url") {
							body = `{"data":{"id":"2244994945","name":"Jane Reader","username":"janereader",
								"profile_image_url":"https://pbs.twimg.com/profile_images/1/photo_normal.jpg"}}`
						}
					}
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, err := w.Write([]byte(body))
					assert.NoError(t, err)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer x.Close()

			jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
				TokenDuration: time.Hour, CookieDuration: days31})
			prov := NewTwitterV2(Params{URL: loginURL, Cid: "cid", Csecret: "csecret", JwtService: jwtService,
				Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: logger.Std})
			// keep the paths, the queries and the auth style of the provider, send the requests to the mock
			toMock := func(rawURL string) string {
				u, err := url.Parse(rawURL)
				require.NoError(t, err)
				return x.URL + u.RequestURI()
			}
			prov.endpoint.AuthURL, prov.endpoint.TokenURL = toMock(prov.endpoint.AuthURL), toMock(prov.endpoint.TokenURL)
			prov.infoURL = toMock(prov.infoURL)
			prov.conf.Endpoint = prov.endpoint
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

			assert.Equal(t, c.wantStatus, resp.StatusCode, "got body %s", string(body))
			mu.Lock()
			assert.Equal(t, 1, exchanges, "token requests")
			assert.False(t, secretInBody, "client secret must travel in the basic header only")
			mu.Unlock()

			if c.wantStatus != http.StatusOK {
				assert.NotContains(t, string(body), "twitter_", "no user may be mapped from a failed login")
				assert.Empty(t, resp.Cookies(), "no auth cookie on failed login")
				return
			}
			u := token.User{}
			require.NoError(t, json.Unmarshal(body, &u))
			assert.Equal(t, token.User{Name: "janereader", ID: "twitter_5bacdefab92b37af7de1ff347033776d65929df2",
				Picture: "http://example.com/ava12345.png"}, u)
			require.Equal(t, 2, len(resp.Cookies()))
			assert.Equal(t, "JWT", resp.Cookies()[0].Name)
		})
	}
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
