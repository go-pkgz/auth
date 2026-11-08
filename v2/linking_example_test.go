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
	mu      sync.Mutex
	pending map[string]*pendingLink // by nonce
	data    map[string][]string     // app records by user id
}

type pendingLink struct {
	anonID  string
	address string // email address typed when the link started, binds the identity allowed to receive the data
	shownTo string // user id the confirmation screen named
	expires time.Time
}

const linkCookie = "link_nonce"

func newLinkApp() *linkApp {
	return &linkApp{pending: map[string]*pendingLink{}, data: map[string][]string{}}
}

// cookieTokenOnly rejects a token passed as ?token= or in the JWT header: the middleware accepts those
// before the cookie and checks no XSRF header for them.
func cookieTokenOnly(r *http.Request) bool {
	return r.URL.Query().Get("token") == "" && r.Header.Get("X-JWT") == ""
}

// start runs behind the auth middleware, before the frontend sends an anonymous user to a real provider
func (a *linkApp) start(w http.ResponseWriter, r *http.Request) {
	user := token.MustGetUserInfo(r)
	if r.Method != http.MethodPost || !cookieTokenOnly(r) || !strings.HasPrefix(user.ID, "anonymous_") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(b)
	a.mu.Lock()
	a.pending[nonce] = &pendingLink{anonID: user.ID, address: r.FormValue("address"), expires: time.Now().Add(10 * time.Minute)}
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
	if !cookieTokenOnly(r) || strings.HasPrefix(user.ID, "anonymous_") {
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

	switch r.Method {
	case http.MethodGet:
		// the display name is not proof: for email it comes from the user query parameter.
		// bind the identity to the address typed at start instead.
		if p.address != "" && user.ID != "email_"+token.HashID(sha1.New(), p.address) { //nolint:gosec
			http.Error(w, "logged in as a different address", http.StatusForbidden)
			return
		}
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

func newLinkEnv(t *testing.T) *linkEnv {
	t.Helper()
	env := &linkEnv{app: newLinkApp(), letter: map[string]string{}}
	ts := httptest.NewUnstartedServer(nil)
	env.url = "http://" + ts.Listener.Addr().String()

	svc := NewService(Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour,
		Issuer:         "link-test",
		URL:            env.url,
	})
	// anonymous ids carry a random part, so a second user typing the same name gets another id
	svc.AddDirectProviderWithUserIDFunc("anonymous",
		provider.CredCheckerFunc(func(string, string) (bool, error) { return true, nil }),
		func(user string, _ *http.Request) string { return user + "::" + rand.Text() })
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

func emailID(address string) string { return "email_" + token.HashID(sha1.New(), address) } //nolint:gosec

func TestLinkAnonymousUser(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	assert.NotEqual(t, anonID, env.browser(t).loginAnonymous("guest"), "the same name must not give the same anonymous id")
	env.app.data[anonID] = []string{"draft 1", "draft 2"}

	code, _ := victim.do(http.MethodGet, "/link/start", nil)
	assert.Equal(t, http.StatusForbidden, code, "start is POST only, so a plain link cannot trigger it")
	code, body := victim.do(http.MethodPost, "/link/start", url.Values{"address": {"victim@example.com"}})
	require.Equal(t, http.StatusNoContent, code, body)

	victim.openEmailLink(victim.requestEmailLink("victim", "victim@example.com"))
	require.Equal(t, emailID("victim@example.com"), victim.user().ID)

	moveTo := url.Values{"move_to": {emailID("victim@example.com")}}
	code, _ = victim.do(http.MethodPost, "/link/confirm", moveTo)
	assert.Equal(t, http.StatusConflict, code, "nothing moves before the confirmation screen named the account")

	code, body = victim.do(http.MethodGet, "/link/confirm", nil)
	require.Equal(t, http.StatusOK, code, body)
	assert.Contains(t, body, emailID("victim@example.com"))

	nonce := victim.cookie(linkCookie)
	require.NotNil(t, nonce)
	code, body = victim.do(http.MethodPost, "/link/confirm", moveTo)
	require.Equal(t, http.StatusNoContent, code, body)
	assert.Equal(t, []string{"draft 1", "draft 2"}, env.app.data[emailID("victim@example.com")])
	assert.Empty(t, env.app.data[anonID])

	// replaying the nonce, as a second tab or a captured cookie would, finds nothing to move
	victim.setCookie(nonce)
	code, _ = victim.do(http.MethodPost, "/link/confirm", moveTo)
	assert.Equal(t, http.StatusConflict, code, "a link is consumed once")

	code, _ = victim.do(http.MethodPost, "/link/start", url.Values{"address": {"victim@example.com"}})
	assert.Equal(t, http.StatusForbidden, code, "only an anonymous user can start a link")
}

func TestLinkAnonymousUser_AttackerConfirmationLink(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	code, body := victim.do(http.MethodPost, "/link/start", url.Values{"address": {"victim@example.com"}})
	require.Equal(t, http.StatusNoContent, code, body)

	// the attacker requests a letter for his own address and gets the victim to open it,
	// which logs the victim's browser into the attacker's account
	attackerLink := env.browser(t).requestEmailLink("victim", "attacker@example.com")
	victim.openEmailLink(attackerLink)
	require.Equal(t, emailID("attacker@example.com"), victim.user().ID)

	code, _ = victim.do(http.MethodGet, "/link/confirm", nil)
	assert.Equal(t, http.StatusForbidden, code, "the account must match the address typed at start")
	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {emailID("attacker@example.com")}})
	assert.Equal(t, http.StatusConflict, code)
	assert.Equal(t, []string{"draft"}, env.app.data[anonID], "the data stays with the anonymous user")
	assert.Empty(t, env.app.data[emailID("attacker@example.com")])
}

func TestLinkAnonymousUser_ConfirmNeedsRealLogin(t *testing.T) {
	// without an address to bind, as for Telegram or an oauth provider, confirm still refuses an anonymous user
	env := newLinkEnv(t)
	guest := env.browser(t)
	anonID := guest.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	code, body := guest.do(http.MethodPost, "/link/start", nil)
	require.Equal(t, http.StatusNoContent, code, body)

	code, _ = guest.do(http.MethodGet, "/link/confirm", nil)
	assert.Equal(t, http.StatusForbidden, code)
	code, _ = guest.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {anonID}})
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, []string{"draft"}, env.app.data[anonID])
}

func TestLinkAnonymousUser_AccountSwitchAfterConfirmScreen(t *testing.T) {
	// no address to bind, as for Telegram or an oauth provider. The screen showed account A, then the
	// browser got logged into B (an attacker's Telegram or email link) and a page reload showed B.
	// A click on the old screen still names A, and must not move the data to B.
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	code, body := victim.do(http.MethodPost, "/link/start", nil)
	require.Equal(t, http.StatusNoContent, code, body)

	victim.openEmailLink(victim.requestEmailLink("victim", "a@example.com"))
	code, body = victim.do(http.MethodGet, "/link/confirm", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, emailID("a@example.com"))

	victim.openEmailLink(env.browser(t).requestEmailLink("victim", "b@example.com"))
	require.Equal(t, emailID("b@example.com"), victim.user().ID)

	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {emailID("b@example.com")}})
	assert.Equal(t, http.StatusConflict, code, "B was never shown, so naming B must not move the data")

	code, body = victim.do(http.MethodGet, "/link/confirm", nil) // a reload in another tab shows B
	require.Equal(t, http.StatusOK, code, body)
	code, _ = victim.do(http.MethodPost, "/link/confirm", url.Values{"move_to": {emailID("a@example.com")}})
	assert.Equal(t, http.StatusConflict, code, "the old screen names A while B is logged in")
	assert.Equal(t, []string{"draft"}, env.app.data[anonID], "the data stays with the anonymous user")
	assert.Empty(t, env.app.data[emailID("b@example.com")])
}

func TestLinkAnonymousUser_ExpiredLink(t *testing.T) {
	env := newLinkEnv(t)
	victim := env.browser(t)
	anonID := victim.loginAnonymous("guest")
	env.app.data[anonID] = []string{"draft"}
	code, body := victim.do(http.MethodPost, "/link/start", url.Values{"address": {"victim@example.com"}})
	require.Equal(t, http.StatusNoContent, code, body)
	env.app.mu.Lock()
	for _, p := range env.app.pending {
		p.expires = time.Now().Add(-time.Second)
	}
	env.app.mu.Unlock()

	victim.openEmailLink(victim.requestEmailLink("victim", "victim@example.com"))
	code, _ = victim.do(http.MethodGet, "/link/confirm", nil)
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

	// a token in the query or the JWT header is accepted by the middleware without an XSRF check,
	// so a cross-site request could carry it; the link endpoints refuse it
	stranger := env.browser(t)
	code, _ := stranger.do(http.MethodPost, "/link/start?token="+url.QueryEscape(jwt), url.Values{"address": {"x@example.com"}})
	assert.Equal(t, http.StatusForbidden, code)
	code, _ = stranger.doWithHeader(http.MethodPost, "/link/start", url.Values{"address": {"x@example.com"}},
		http.Header{"X-JWT": {jwt}})
	assert.Equal(t, http.StatusForbidden, code)
	assert.Empty(t, env.app.pending)

	code, body := victim.do(http.MethodPost, "/link/start", url.Values{"address": {"victim@example.com"}})
	require.Equal(t, http.StatusNoContent, code, body)
	victim.openEmailLink(victim.requestEmailLink("victim", "victim@example.com"))
	realJWT := victim.cookie("JWT")
	require.NotNil(t, realJWT)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		code, _ = stranger.do(method, "/link/confirm?token="+url.QueryEscape(realJWT.Value), nil)
		assert.Equal(t, http.StatusForbidden, code, method)
		code, _ = stranger.doWithHeader(method, "/link/confirm", nil, http.Header{"X-JWT": {realJWT.Value}})
		assert.Equal(t, http.StatusForbidden, code, method)
	}
}
