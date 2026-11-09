package auth

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the email provider derives user ids with sha1
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/v2/provider"
	"github.com/go-pkgz/auth/v2/token"
)

// linkApp is the application side of linking an anonymous user to the identity they log in with
// afterwards, as described in the README section "Linking an anonymous user after login".
// auth keeps no users, so the pending link and the data live in the app.
type linkApp struct {
	mu        sync.Mutex
	jwtQuery  string                  // Opts.JWTQuery, "token" by default
	jwtHeader string                  // Opts.JWTHeaderKey, "X-JWT" by default
	providers map[string]bool         // providers a link may move the data to
	pending   map[string]*pendingLink // by nonce
	data      map[string][]string     // app records by user id
}

type pendingLink struct {
	anonID   string
	provider string // provider the user is about to log in with, only its users can receive the data
	address  string // for email, the address typed at start, only its user id can receive the data
	shownTo  string // user id the confirmation screen named
	expires  time.Time
}

const linkCookie = "link_nonce"

// newLinkApp takes the JWT query and header names from Opts. Opts keeps them empty when left to the
// library defaults, and an empty name would make cookieTokenOnly match nothing, so it falls back to them.
func newLinkApp(jwtQuery, jwtHeader string, providers ...string) *linkApp {
	if jwtQuery == "" {
		jwtQuery = "token"
	}
	if jwtHeader == "" {
		jwtHeader = "X-JWT"
	}
	a := &linkApp{jwtQuery: jwtQuery, jwtHeader: jwtHeader, providers: map[string]bool{},
		pending: map[string]*pendingLink{}, data: map[string][]string{}}
	for _, p := range providers {
		a.providers[p] = true
	}
	return a
}

// cookieTokenOnly rejects a token passed in the query or the JWT header: the middleware accepts those
// before the cookie and checks no XSRF header for them.
func (a *linkApp) cookieTokenOnly(r *http.Request) bool {
	return r.URL.Query().Get(a.jwtQuery) == "" && r.Header.Get(a.jwtHeader) == ""
}

// accepts tells whether userID may receive the data. The display name is no proof, for email it comes
// from the user query parameter. An email link binds the exact address typed at start. Any other
// provider binds only the provider, so its user has to recognize the account on the confirmation screen.
func (p *pendingLink) accepts(userID string) bool {
	if p.provider == "email" {
		return userID == "email_"+token.HashID(sha1.New(), p.address) //nolint:gosec
	}
	return strings.HasPrefix(userID, p.provider+"_")
}

// start runs behind the auth middleware, before the frontend sends an anonymous user to a real provider
func (a *linkApp) start(w http.ResponseWriter, r *http.Request) {
	user := token.MustGetUserInfo(r)
	if r.Method != http.MethodPost || !a.cookieTokenOnly(r) || !strings.HasPrefix(user.ID, "anonymous_") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	prov, address := r.FormValue("provider"), r.FormValue("address")
	if !a.providers[prov] || (prov == "email") != (address != "") {
		http.Error(w, "a known provider is required, and an address for email only", http.StatusBadRequest)
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(b)
	a.mu.Lock()
	a.pending[nonce] = &pendingLink{anonID: user.ID, provider: prov, address: address, expires: time.Now().Add(10 * time.Minute)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: linkCookie, Value: nonce, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: 600})
	w.WriteHeader(http.StatusNoContent)
}

// lookup returns the live pending link for the request's nonce cookie, under a.mu
func (a *linkApp) lookup(r *http.Request) (*pendingLink, string) {
	c, err := r.Cookie(linkCookie)
	if err != nil {
		return nil, ""
	}
	p, ok := a.pending[c.Value]
	if !ok || time.Now().After(p.expires) {
		return nil, ""
	}
	return p, c.Value
}

// confirm shows on GET which account the data would move to, and moves it on POST, both behind the middleware
func (a *linkApp) confirm(w http.ResponseWriter, r *http.Request) {
	user := token.MustGetUserInfo(r)
	// a confirm by the anonymous user itself would append the data to itself and then delete it.
	// accepts refuses it too while "anonymous" is not a link provider, this check does not depend on that.
	if !a.cookieTokenOnly(r) || strings.HasPrefix(user.ID, "anonymous_") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p, nonce := a.lookup(r)
	if p == nil {
		http.Error(w, "no pending link", http.StatusConflict)
		return
	}
	if !p.accepts(user.ID) {
		http.Error(w, "logged in with another account than the link was started for", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p.shownTo = user.ID
		_ = json.NewEncoder(w).Encode(map[string]string{"move_to": user.ID})
	case http.MethodPost:
		// move_to is the account the screen named. a later GET from another tab may have shown another
		// account, so the POST must name the same account that is logged in and was last shown.
		if moveTo := r.FormValue("move_to"); moveTo == "" || moveTo != user.ID || p.shownTo != user.ID {
			http.Error(w, "confirm the account shown first", http.StatusConflict)
			return
		}
		// one critical section stands in for one DB transaction: move and consume together
		a.data[user.ID] = append(a.data[user.ID], a.data[p.anonID]...)
		delete(a.data, p.anonID)
		delete(a.pending, nonce)
		http.SetCookie(w, &http.Cookie{Name: linkCookie, Path: "/", MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type linkEnv struct {
	url    string
	app    *linkApp
	mu     sync.Mutex
	letter map[string]string // last confirmation token sent, by address
}

// non-default names, so a check hardcoding "token" and "X-JWT" fails the tests
const linkJWTQuery, linkJWTHeader = "jwt", "X-Link-JWT"

func newLinkEnv(t *testing.T) *linkEnv {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	opts := Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour,
		Issuer:         "link-test",
		URL:            "http://" + ts.Listener.Addr().String(),
		JWTQuery:       linkJWTQuery,
		JWTHeaderKey:   linkJWTHeader,
	}
	env := &linkEnv{url: opts.URL, app: newLinkApp(opts.JWTQuery, opts.JWTHeaderKey, "email", "password"),
		letter: map[string]string{}}
	svc := NewService(opts)
	// anonymous ids carry a random part, so a second user typing the same name gets another id
	svc.AddDirectProviderWithUserIDFunc("anonymous",
		provider.CredCheckerFunc(func(string, string) (bool, error) { return true, nil }),
		func(user string, _ *http.Request) string { return user + "::" + rand.Text() })
	svc.AddDirectProvider("password", provider.CredCheckerFunc(func(user, password string) (bool, error) {
		return password == "pw-"+user, nil
	}))
	svc.AddVerifProvider("email", "{{.Token}}", provider.SenderFunc(func(address, text string) error {
		env.mu.Lock()
		env.letter[address] = text
		env.mu.Unlock()
		return nil
	}))

	m := svc.Middleware()
	authRoutes, _ := svc.Handlers()
	mux := http.NewServeMux()
	mux.Handle("/auth/", authRoutes)
	mux.Handle("/link/start", m.Auth(http.HandlerFunc(env.app.start)))
	mux.Handle("/link/confirm", m.Auth(http.HandlerFunc(env.app.confirm)))
	ts.Config.Handler = mux
	ts.Start()
	t.Cleanup(ts.Close)
	return env
}

// browser is an http client with a cookie jar that sends the XSRF header the way a frontend does
type browser struct {
	t      *testing.T
	env    *linkEnv
	client *http.Client
}

func (env *linkEnv) browser(t *testing.T) *browser {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, env: env, client: &http.Client{Jar: jar, Timeout: 5 * time.Second}}
}

func (b *browser) do(method, path string, form url.Values) (int, string) {
	b.t.Helper()
	return b.doWithHeader(method, path, form, nil)
}

func (b *browser) doWithHeader(method, path string, form url.Values, header http.Header) (int, string) {
	b.t.Helper()
	req, err := http.NewRequest(method, b.env.url+path, strings.NewReader(form.Encode()))
	require.NoError(b.t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	u, err := url.Parse(b.env.url)
	require.NoError(b.t, err)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == "XSRF-TOKEN" {
			req.Header.Set("X-XSRF-TOKEN", c.Value)
		}
	}
	resp, err := b.client.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(b.t, err)
	return resp.StatusCode, string(body)
}

func (b *browser) cookie(name string) *http.Cookie {
	u, err := url.Parse(b.env.url)
	require.NoError(b.t, err)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name {
			return &http.Cookie{Name: c.Name, Value: c.Value, Path: "/"}
		}
	}
	return nil
}

func (b *browser) setCookie(c *http.Cookie) {
	u, err := url.Parse(b.env.url)
	require.NoError(b.t, err)
	b.client.Jar.SetCookies(u, []*http.Cookie{c})
}

func (b *browser) user() token.User {
	code, body := b.do(http.MethodGet, "/auth/user", nil)
	require.Equal(b.t, http.StatusOK, code, body)
	var u token.User
	require.NoError(b.t, json.Unmarshal([]byte(body), &u))
	return u
}

func (b *browser) loginAnonymous(name string) string {
	code, body := b.do(http.MethodGet, "/auth/anonymous/login?aud=link-test&passwd=x&user="+url.QueryEscape(name), nil)
	require.Equal(b.t, http.StatusOK, code, body)
	return b.user().ID
}

func (b *browser) startLink(form url.Values) {
	code, body := b.do(http.MethodPost, "/link/start", form)
	require.Equal(b.t, http.StatusNoContent, code, body)
}

// requestEmailLink asks for a confirmation letter, from any browser, and returns the token sent to address
func (b *browser) requestEmailLink(name, address string) string {
	code, body := b.do(http.MethodGet, "/auth/email/login?aud=link-test&user="+url.QueryEscape(name)+
		"&address="+url.QueryEscape(address), nil)
	require.Equal(b.t, http.StatusOK, code, body)
	b.env.mu.Lock()
	defer b.env.mu.Unlock()
	return b.env.letter[address]
}

func (b *browser) openEmailLink(tkn string) {
	code, body := b.do(http.MethodGet, "/auth/email/login?token="+url.QueryEscape(tkn), nil)
	require.Equal(b.t, http.StatusOK, code, body)
}

// openPasswordLink opens the login link of a password account, which its owner can send to anyone
func (b *browser) openPasswordLink(name string) {
	code, body := b.do(http.MethodGet, "/auth/password/login?aud=link-test&user="+url.QueryEscape(name)+
		"&passwd="+url.QueryEscape("pw-"+name), nil)
	require.Equal(b.t, http.StatusOK, code, body)
}

func emailID(address string) string { return "email_" + token.HashID(sha1.New(), address) } //nolint:gosec

func emailLink(address string) url.Values {
	return url.Values{"provider": {"email"}, "address": {address}}
}

var passwordLink = url.Values{"provider": {"password"}}

func TestLinkAnonymousUser(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	assert.NotEqual(t, anonID, env.browser(t).loginAnonymous("guest"), "the same name must not give the same anonymous id")
	env.app.data[anonID] = []string{"draft 1", "draft 2"}

	code, _ := victim.do(http.MethodGet, "/link/start", nil)
	assert.Equal(t, http.StatusForbidden, code, "start is POST only, so a plain link cannot trigger it")
	victim.startLink(emailLink("victim@example.com"))

	victim.openEmailLink(victim.requestEmailLink("victim", "victim@example.com"))
	require.Equal(t, emailID("victim@example.com"), victim.user().ID)

	moveTo := url.Values{"move_to": {emailID("victim@example.com")}}
	code, _ = victim.do(http.MethodPost, "/link/confirm", moveTo)
	assert.Equal(t, http.StatusConflict, code, "nothing moves before the confirmation screen named the account")

	code, body := victim.do(http.MethodGet, "/link/confirm", nil)
	require.Equal(t, http.StatusOK, code, body)
	assert.Contains(t, body, emailID("victim@example.com"))

	nonce := victim.cookie(linkCookie)
	require.NotNil(t, nonce)
	code, body = victim.do(http.MethodPost, "/link/confirm", moveTo)
	require.Equal(t, http.StatusNoContent, code, body)
	assert.Equal(t, []string{"draft 1", "draft 2"}, env.app.data[emailID("victim@example.com")])
	assert.Empty(t, env.app.data[anonID])

	victim.setCookie(nonce)
	code, _ = victim.do(http.MethodPost, "/link/confirm", moveTo)
	assert.Equal(t, http.StatusConflict, code, "a replayed nonce, from a second tab or a captured cookie, finds nothing to move")

	code, _ = victim.do(http.MethodPost, "/link/start", emailLink("victim@example.com"))
	assert.Equal(t, http.StatusForbidden, code, "only an anonymous user can start a link")
}

func TestLinkAnonymousUser_PasswordProvider(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	victim.startLink(passwordLink)

	victim.openPasswordLink("alice")
	alice := victim.user().ID
	code, body := victim.do(http.MethodGet, "/link/confirm", nil)
	require.Equal(t, http.StatusOK, code, body)
	code, body = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {alice}})
	require.Equal(t, http.StatusNoContent, code, body)
	assert.Equal(t, []string{"draft"}, env.app.data[alice])
	assert.Empty(t, env.app.data[anonID])
}

func TestLinkAnonymousUser_StartNeedsKnownProvider(t *testing.T) {
	tbl := []struct {
		name string
		form url.Values
	}{
		{"no provider", nil},
		{"unknown provider", url.Values{"provider": {"github"}}},
		{"anonymous provider", url.Values{"provider": {"anonymous"}}},
		{"email without address", url.Values{"provider": {"email"}}},
		{"address for a provider other than email", url.Values{"provider": {"password"}, "address": {"a@example.com"}}},
	}
	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			env := newLinkEnv(t)
			guest := env.browser(t)
			guest.loginAnonymous("guest")
			code, _ := guest.do(http.MethodPost, "/link/start", tt.form)
			assert.Equal(t, http.StatusBadRequest, code)
			assert.Empty(t, env.app.pending)
		})
	}
}

func TestLinkAnonymousUser_AttackerConfirmationLink(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	victim.startLink(emailLink("victim@example.com"))

	attackerLink := env.browser(t).requestEmailLink("victim", "attacker@example.com")
	victim.openEmailLink(attackerLink)
	require.Equal(t, emailID("attacker@example.com"), victim.user().ID, "the attacker's letter logs the victim's browser in")

	code, _ := victim.do(http.MethodGet, "/link/confirm", nil)
	assert.Equal(t, http.StatusForbidden, code, "the account must match the address typed at start")
	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {emailID("attacker@example.com")}})
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, []string{"draft"}, env.app.data[anonID], "the data stays with the anonymous user")
	assert.Empty(t, env.app.data[emailID("attacker@example.com")])
}

func TestLinkAnonymousUser_LoginWithAnotherProvider(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	victim.startLink(passwordLink)

	victim.openEmailLink(env.browser(t).requestEmailLink("victim", "attacker@example.com"))
	require.Equal(t, emailID("attacker@example.com"), victim.user().ID, "the attacker's letter logs the victim's browser in")

	code, _ := victim.do(http.MethodGet, "/link/confirm", nil)
	assert.Equal(t, http.StatusForbidden, code, "a link started for the password provider must not offer an email account")
	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {emailID("attacker@example.com")}})
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, []string{"draft"}, env.app.data[anonID], "the data stays with the anonymous user")
	assert.Empty(t, env.app.data[emailID("attacker@example.com")])
}

func TestLinkAnonymousUser_ConfirmNeedsRealLogin_EvenWithAnonymousProviderAllowed(t *testing.T) {
	env := newLinkEnv(t)
	env.app.providers["anonymous"] = true
	guest := env.browser(t)
	anonID := guest.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	guest.startLink(url.Values{"provider": {"anonymous"}})

	code, _ := guest.do(http.MethodGet, "/link/confirm", nil)
	assert.Equal(t, http.StatusForbidden, code, "confirm refuses a user who is still anonymous, even when accepts lets him through")
	code, _ = guest.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {anonID}})
	assert.Equal(t, http.StatusForbidden, code, "confirm refuses a user who is still anonymous, even when accepts lets him through")
	assert.Equal(t, []string{"draft"}, env.app.data[anonID])
}

func TestLinkAnonymousUser_AccountSwitchAfterConfirmScreen(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	victim.startLink(passwordLink)

	victim.openPasswordLink("alice")
	alice := victim.user().ID
	code, body := victim.do(http.MethodGet, "/link/confirm", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, alice)

	victim.openPasswordLink("mallory")
	mallory := victim.user().ID
	require.NotEqual(t, alice, mallory, "the attacker's login link logs the victim's browser into his account")

	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {mallory}})
	assert.Equal(t, http.StatusConflict, code, "an account the screen never named must not receive the data")

	code, body = victim.do(http.MethodGet, "/link/confirm", nil)
	require.Equal(t, http.StatusOK, code, body, "a reload in another tab names the attacker's account")
	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {alice}})
	assert.Equal(t, http.StatusConflict, code, "the old screen names alice while the attacker is logged in")
	assert.Equal(t, []string{"draft"}, env.app.data[anonID], "the data stays with the anonymous user")
	assert.Empty(t, env.app.data[mallory])
}

func TestLinkAnonymousUser_ExpiredLink(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	victim.startLink(emailLink("victim@example.com"))
	env.app.mu.Lock()
	for _, p := range env.app.pending {
		p.expires = time.Now().Add(-time.Second)
	}
	env.app.mu.Unlock()

	victim.openEmailLink(victim.requestEmailLink("victim", "victim@example.com"))
	code, _ := victim.do(http.MethodGet, "/link/confirm", nil)
	assert.Equal(t, http.StatusConflict, code, "an expired link offers nothing to move")
	assert.Equal(t, []string{"draft"}, env.app.data[anonID])
}

func TestLinkAnonymousUser_RejectsNonCookieToken(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	victim.loginAnonymous("guest")
	jwtCookie := victim.cookie("JWT")
	require.NotNil(t, jwtCookie)
	jwt := jwtCookie.Value

	const why = "the middleware takes a query or header token without an XSRF check, so a cross-site request could carry it"
	stranger := env.browser(t)
	code, _ := stranger.do(http.MethodPost, "/link/start?"+linkJWTQuery+"="+url.QueryEscape(jwt), emailLink("x@example.com"))
	assert.Equal(t, http.StatusForbidden, code, why)
	code, _ = stranger.doWithHeader(http.MethodPost, "/link/start", emailLink("x@example.com"), http.Header{linkJWTHeader: {jwt}})
	assert.Equal(t, http.StatusForbidden, code, why)
	assert.Empty(t, env.app.pending)

	victim.startLink(emailLink("victim@example.com"))
	victim.openEmailLink(victim.requestEmailLink("victim", "victim@example.com"))
	realJWT := victim.cookie("JWT")
	require.NotNil(t, realJWT)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		code, _ = stranger.do(method, "/link/confirm?"+linkJWTQuery+"="+url.QueryEscape(realJWT.Value), nil)
		assert.Equal(t, http.StatusForbidden, code, method+": "+why)
		code, _ = stranger.doWithHeader(method, "/link/confirm", nil, http.Header{linkJWTHeader: {realJWT.Value}})
		assert.Equal(t, http.StatusForbidden, code, method+": "+why)
	}
}

func TestLinkAnonymousUser_DefaultJWTNames(t *testing.T) {
	a := newLinkApp("", "") // Opts left at the library defaults keeps both names empty
	r := httptest.NewRequest(http.MethodPost, "/link/start?token=x", http.NoBody)
	assert.False(t, a.cookieTokenOnly(r), "a token in the default query parameter must be refused")
	r = httptest.NewRequest(http.MethodPost, "/link/start", http.NoBody)
	r.Header.Set("X-JWT", "x")
	assert.False(t, a.cookieTokenOnly(r), "a token in the default header must be refused")
	assert.True(t, a.cookieTokenOnly(httptest.NewRequest(http.MethodPost, "/link/start", http.NoBody)))
}

func TestLinkAnonymousUser_NonceCookieAttributes(t *testing.T) {
	a := newLinkApp("", "", "password")
	r := httptest.NewRequest(http.MethodPost, "/link/start", strings.NewReader("provider=password"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = token.SetUserInfo(r, token.User{ID: "anonymous_1"})
	w := httptest.NewRecorder()
	a.start(w, r)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, linkCookie, cookies[0].Name)
	assert.True(t, cookies[0].HttpOnly, "page scripts must not read the nonce")
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite, "a cross-site POST to confirm must not carry the nonce")
}
