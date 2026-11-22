package provider

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dghubble/oauth1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

// loginResult is what the browser gets back from the provider callback
type loginResult struct {
	status  int
	body    string
	cookies []*http.Cookie
}

func TestProviders_LoginRefusesAnswerWithoutUserID(t *testing.T) {
	githubNumeric := func(p Params) Oauth2Handler {
		p.GithubNumericID = true
		return NewGithub(p)
	}
	tbl := []struct {
		name    string
		newProv func(Params) Oauth2Handler
		withID  string   // a 2xx answer with the user id, the login must succeed
		noID    []string // 2xx answers without a usable user id, the login must fail
	}{
		{name: "google", newProv: NewGoogle, withID: `{"sub":"1234567890","name":"blah"}`,
			noID: []string{`{"name":"blah"}`, `{"sub":null,"name":"blah"}`, `{"sub":"","name":"blah"}`}},
		{name: "github", newProv: NewGithub, withID: `{"login":"lll","name":"blah"}`,
			noID: []string{`{"name":"blah"}`, `{"login":null,"name":"blah"}`, `{"login":"","name":"blah","id":1345027}`}},
		{name: "github numeric id", newProv: githubNumeric, withID: `{"id":1345027,"name":"blah"}`,
			noID: []string{`{"name":"blah"}`, `{"login":null,"id":null,"name":"blah"}`, `{"login":"","id":0,"name":"blah"}`}},
		{name: "facebook", newProv: NewFacebook, withID: `{"id":"1234567890","name":"blah"}`,
			noID: []string{`{"name":"blah"}`, `{"id":null,"name":"blah"}`, `{"id":"","name":"blah"}`}},
		{name: "yandex", newProv: NewYandex, withID: `{"id":"1234567890","display_name":"blah"}`,
			noID: []string{`{"display_name":"blah"}`, `{"id":null,"display_name":"blah"}`, `{"id":"","display_name":"blah"}`}},
		{name: "battlenet", newProv: NewBattlenet, withID: `{"id":12345678,"battletag":"blah"}`,
			noID: []string{`{"battletag":"blah"}`, `{"id":null,"battletag":"blah"}`, `{"id":"","battletag":"blah"}`}},
		{name: "microsoft", newProv: NewMicrosoft, withID: `{"id":"1234567890","displayName":"blah"}`,
			noID: []string{`{"displayName":"blah"}`, `{"id":null,"displayName":"blah"}`, `{"id":"","displayName":"blah"}`}},
		{name: "patreon", newProv: NewPatreon, withID: `{"data":{"id":"1234567890","attributes":{"full_name":"blah"}}}`,
			noID: []string{`{"data":{"attributes":{"full_name":"blah"}}}`, `{"data":{"id":null,"attributes":{"full_name":"blah"}}}`,
				`{"data":{"id":"","attributes":{"full_name":"blah"}}}`}},
		{name: "discord", newProv: NewDiscord, withID: `{"id":"1234567890","username":"blah"}`,
			noID: []string{`{"username":"blah"}`, `{"id":null,"username":"blah"}`, `{"id":"","username":"blah"}`}},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			// the same flow with the id present logs in, so a refusal below comes from the missing id
			res := oauth2LoginWithUserInfo(t, tt.newProv, tt.withID)
			require.Equal(t, http.StatusOK, res.status, "login with an id must pass, got body %s", res.body)
			require.NotEmpty(t, res.cookies, "auth cookie on successful login")

			for _, info := range tt.noID {
				res := oauth2LoginWithUserInfo(t, tt.newProv, info)
				assert.Equal(t, http.StatusServiceUnavailable, res.status, "answer %s must not log in, got body %s", info, res.body)
				assert.Contains(t, res.body, "failed to get user info", "answer %s", info)
				assert.NotContains(t, res.body, "blah", "no user may be mapped without an id, answer %s", info)
				assert.Empty(t, res.cookies, "no auth cookie on failed login, answer %s", info)
			}
		})
	}

	t.Run("twitter", func(t *testing.T) {
		res := oauth1LoginWithUserInfo(t, NewTwitter, `{"id_str":"1234567890","screen_name":"blah"}`)
		require.Equal(t, http.StatusOK, res.status, "login with an id must pass, got body %s", res.body)
		require.NotEmpty(t, res.cookies, "auth cookie on successful login")

		for _, info := range []string{`{"screen_name":"blah"}`, `{"id_str":null,"screen_name":"blah"}`, `{"id_str":"","screen_name":"blah"}`} {
			res := oauth1LoginWithUserInfo(t, NewTwitter, info)
			assert.Equal(t, http.StatusServiceUnavailable, res.status, "answer %s must not log in, got body %s", info, res.body)
			assert.Contains(t, res.body, "failed to get user info", "answer %s", info)
			assert.NotContains(t, res.body, "blah", "no user may be mapped without an id, answer %s", info)
			assert.Empty(t, res.cookies, "no auth cookie on failed login, answer %s", info)
		}
	})
}

func TestOauth1LoginRejectsEmptyUserID(t *testing.T) {
	// a user mapped without an id would be the same user for everyone mapped that way
	mockProv := func(p Params) Oauth1Handler {
		return initOauth1Handler(p, Oauth1Handler{
			name: "mock",
			mapUser: func(data UserData, _ []byte) token.User {
				return token.User{ID: data.Value("id"), Name: data.Value("name")}
			},
		})
	}
	res := oauth1LoginWithUserInfo(t, mockProv, `{"name":"blah"}`)
	assert.Equal(t, http.StatusServiceUnavailable, res.status, "login must fail, got body %s", res.body)
	assert.NotContains(t, res.body, "blah", "no user may be mapped without an id")
	assert.Empty(t, res.cookies, "no auth cookie on failed login")
}

func TestProviders_GithubNumericIDWithoutLogin(t *testing.T) {
	// the numeric account id identifies the user on its own
	r := NewGithub(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs", GithubNumericID: true})
	user := r.mapUser(UserData{"name": "test user"}, []byte(`{"id": 1345027}`))
	assert.Equal(t, "github_d4dc5da9a1e6bbd5d77920e4ea2ca91707e59083", user.ID)
	assert.Equal(t, "", r.mapUser(UserData{"name": "test user"}, []byte(`{"id": 0}`)).ID, "no login and no numeric id")
}

func TestProviders_NewBattlenet(t *testing.T) {
	r := NewBattlenet(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "battlenet", r.Name())
	// battle.net answers with a numeric id, the id is the hash of its default formatting
	user := r.mapUser(UserData{"id": float64(12345678), "battletag": "test#1234"}, nil)
	assert.Equal(t, token.User{Name: "test#1234", ID: "battlenet_41a894aa9ddfb433faafba95e8a7a56a5d2c01bd"}, user)
	assert.Equal(t, token.User{}, r.mapUser(UserData{"battletag": "test#1234"}, nil), "no id")
}

// oauth2LoginWithUserInfo runs the login flow of a provider made by newProv against a mock oauth2 server
// which answers the user info request with userInfo
func oauth2LoginWithUserInfo(t *testing.T, newProv func(Params) Oauth2Handler, userInfo string) loginResult {
	t.Helper()
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
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, err := w.Write([]byte(userInfo))
			assert.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer oauth.Close()

	prov := newProv(providerTestParams(loginURL))
	prov.endpoint = oauth2.Endpoint{AuthURL: oauth.URL + "/login/oauth/authorize", TokenURL: oauth.URL + "/login/oauth/access_token"}
	prov.conf.Endpoint = prov.endpoint
	prov.infoURL = oauth.URL + "/user"
	login.Config.Handler = http.HandlerFunc(Service{Provider: prov}.Handler)
	login.Start()

	return getLogin(t, loginURL)
}

// oauth1LoginWithUserInfo runs the login flow of a provider made by newProv against a mock oauth1 server
// which answers the user info request with userInfo
func oauth1LoginWithUserInfo(t *testing.T, newProv func(Params) Oauth1Handler, userInfo string) loginResult {
	t.Helper()
	login := httptest.NewUnstartedServer(nil)
	defer login.Close()
	loginURL := "http://" + login.Listener.Addr().String()

	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		switch {
		case strings.HasPrefix(r.URL.Path, "/login/oauth/request_token"):
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, err = w.Write([]byte("oauth_token=sdjasd09AfdkzztyRadrdR&oauth_token_secret=asd34q129sjdklAJJAs&oauth_callback_confirmed=true"))
		case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
			http.Redirect(w, r, loginURL+"/callback?oauth_token=sdjasd09AfdkzztyRadrdR&oauth_verifier=gsjad032ajjjOIU", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, err = w.Write([]byte("oauth_token=g0ZGZmNjVmOWI&oauth_token_secret=qfr1239UJAkmpaf3l"))
		case strings.HasPrefix(r.URL.Path, "/user"):
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, err = w.Write([]byte(userInfo))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
		assert.NoError(t, err)
	}))
	defer oauth.Close()

	prov := newProv(providerTestParams(loginURL))
	prov.conf.Endpoint = oauth1.Endpoint{
		RequestTokenURL: oauth.URL + "/login/oauth/request_token",
		AuthorizeURL:    oauth.URL + "/login/oauth/authorize",
		AccessTokenURL:  oauth.URL + "/login/oauth/access_token",
	}
	prov.infoURL = oauth.URL + "/user"
	login.Config.Handler = http.HandlerFunc(Service{Provider: prov}.Handler)
	login.Start()

	return getLogin(t, loginURL)
}

func providerTestParams(loginURL string) Params {
	jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})
	return Params{URL: loginURL, Cid: "cid", Csecret: "csecret", JwtService: jwtService,
		Issuer: "remark42", AvatarSaver: &mockAvatarSaver{}, L: logger.NoOp}
}

// getLogin starts a login at loginURL and follows the redirects to the provider callback
func getLogin(t *testing.T, loginURL string) loginResult {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get(loginURL + "/login?site=remark")
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return loginResult{status: resp.StatusCode, body: string(body), cookies: resp.Cookies()}
}
