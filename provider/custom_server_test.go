package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	goauth2 "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

// TestCustomServer_Run_BadURLDoesNotDeadlockShutdown drives the early-return
// branches of CustomServer.Run (URL parse failure and host:port split failure)
// and asserts that Shutdown() can still acquire the mutex afterwards. Before
// the fix, those branches returned with c.lock held; Shutdown would then
// block on the inherited mutex and this test would time out.
func TestCustomServer_Run_BadURLDoesNotDeadlockShutdown(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{name: "unparseable URL", url: "://broken"},
		{name: "URL without port", url: "http://localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &CustomServer{L: logger.NoOp, URL: tc.url}
			c.Run(context.Background())

			done := make(chan struct{})
			go func() {
				c.Shutdown()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Shutdown blocked -- Run left c.lock held on error path")
			}
		})
	}
}

func TestCustomProvider(t *testing.T) {
	router := http.NewServeMux()
	authURL := serveLocal(t, router)
	oauthURL := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	srv := initGoauth2Srv(t, authURL)

	params := Params{
		URL: authURL,
		JwtService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
			DisableIAT:     true,
		}),
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "csecret",
		L:       logger.Std,
	}

	var loginUsername string
	var capturedUser token.User

	sopts := CustomServerOpt{
		URL:           oauthURL,
		L:             logger.Std,
		WithLoginPage: true,
		LoginPageHandler: func(w http.ResponseWriter, r *http.Request) {
			// // simulate POST from login page
			u, err := url.Parse(oauthURL + "/authorize?" + r.URL.RawQuery)
			if err != nil {
				assert.Fail(t, "failed to parse url")
			}

			jar, err := cookiejar.New(nil)
			if err != nil {
				assert.Fail(t, "failed initialize cookiesjar")
			}
			jar.SetCookies(u, r.Cookies())

			form := url.Values{}
			form.Add("username", loginUsername)
			form.Add("password", "pwd1234")

			req, err := http.NewRequest("POST", "", strings.NewReader(form.Encode()))
			if err != nil {
				assert.Fail(t, "failed to simulate POST request in login page ,%s", err)
			}
			req.URL = u
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			c := &http.Client{Jar: jar, Timeout: time.Second * 10}
			resp, err := c.Do(req)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			require.Equal(t, 2, len(resp.Cookies()))
			assert.Equal(t, "JWT", resp.Cookies()[0].Name)
			assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
			assert.Equal(t, 2678400, resp.Cookies()[0].MaxAge)
			assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
			assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

			claims, err := params.JwtService.Parse(resp.Cookies()[0].Value)
			assert.NoError(t, err)

			capturedUser = *claims.User
		},
	}

	prov := NewCustomServer(srv, sopts)

	h := NewCustom("myprov", params, prov.HandlerOpt)
	s := Service{Provider: h}

	router.Handle("/auth/customprov/", http.HandlerFunc(s.Handler))

	ctx := t.Context()

	go prov.Run(ctx)
	defer prov.Shutdown()

	time.Sleep(400 * time.Millisecond)

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: time.Second * 10}

	// check non-admin, permanent
	loginUsername = "admin"
	resp, err := client.Get(authURL + "/auth/customprov/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)
	assert.Equal(t, token.User{Name: "admin", ID: "admin",
		Picture: oauthURL + "/avatar?user=admin", IP: ""}, capturedUser)

	// check avatar
	resp, err = client.Get(oauthURL + "/avatar?user=dev_user")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	// the identicon is encoded by the standard library, so its byte count moves with the Go
	// release: this read 960 until Go 1.27 changed the encoder. Assert the dimensions the
	// generator promises instead, which is what the endpoint owes its caller
	avatarImg, avatarFormat, err := image.Decode(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "png", avatarFormat)
	assert.Equal(t, image.Rect(0, 0, 300, 300), avatarImg.Bounds())
	assert.False(t, uniformImage(avatarImg), "the served avatar is a single flat color")
	t.Logf("headers: %+v", resp.Header)

	// check malicious user ID
	loginUsername = "attack"
	resp, err = client.Get(authURL + "/auth/customprov/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)
	// user ID in picture URL is encoded
	assert.Equal(t, oauthURL+"/avatar?user=none%26attack%3Dvalue%22%3E%3Cscript%3Enasty+stuff%3C%2Fscript%3E", capturedUser.Picture)

	// check default login page
	prov.LoginPageHandler = nil
	resp, err = client.Get(authURL + "/auth/customprov/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	page := string(body)
	assertLoginPageMarkup(t, page)
	assert.Contains(t, page, "<title>Sign in</title>")
	assert.Equal(t, 1, strings.Count(page, "autofocus"), "only the username field takes focus")
	assert.Contains(t, page, `autocomplete="username"`)
	assert.Contains(t, page, `autocomplete="current-password"`)
}

func TestCustomProviderCancel(t *testing.T) {
	srv := initGoauth2Srv(t, "http://127.0.0.1:8080")
	prov := CustomServer{
		OauthServer:   srv,
		URL:           fmt.Sprintf("http://127.0.0.1:%d", freePort(t)),
		L:             logger.Std,
		WithLoginPage: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() {
		prov.Run(ctx)
		done <- true
	}()
	cancel()

	select {
	case <-time.After(time.Second):
		t.Fail()
	case <-done:
	}
}

func initGoauth2Srv(t *testing.T, clientDomain string) *goauth2.Server {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))

	// client memory store
	clientStore := store.NewClientStore()
	err := clientStore.Set("cid", &models.Client{
		ID:     "cid",
		Secret: "csecret",
		Domain: clientDomain,
	})
	if err != nil {
		assert.Fail(t, "failed to set up a client store for go-oauth2/oauth2 server, %s", err)
	}
	manager.MapClientStorage(clientStore)

	srv := goauth2.NewServer(goauth2.NewConfig(), manager)

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		if r.ParseForm() != nil {
			return "", fmt.Errorf("no username and password in request")
		}
		if r.Form.Get("username") == "admin" && r.Form.Get("password") == "pwd1234" {
			return "admin", nil
		}
		if r.Form.Get("username") == "attack" && r.Form.Get("password") == "pwd1234" {
			return "none&attack=value\"><script>nasty stuff</script>", nil
		}
		return "", fmt.Errorf("wrong creds")
	})

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	return srv
}

// recordingAvatarSaver remembers the pictures it was asked to save and answers with its own url
type recordingAvatarSaver struct {
	url      string
	mu       sync.Mutex
	pictures []string
}

func (s *recordingAvatarSaver) Put(u token.User, _ *http.Client) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pictures = append(s.pictures, u.Picture)
	return s.url, nil
}

func (s *recordingAvatarSaver) saved() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pictures
}

func TestNewCustomAvatarSaver(t *testing.T) {
	tbl := []struct {
		name    string
		own     bool
		wantURL string
	}{
		{name: "saver of the provider", own: true, wantURL: "http://example.com/own.png"},
		{name: "saver of the params", wantURL: "http://example.com/params.png"},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			login := httptest.NewUnstartedServer(nil)
			defer login.Close()
			loginURL := "http://" + login.Listener.Addr().String()

			var oauthURL string
			oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/authorize":
					http.Redirect(w, r, loginURL+"/callback?code=g0ZGZmNjVmOWI&state="+url.QueryEscape(r.URL.Query().Get("state")),
						http.StatusFound)
				case "/access_token":
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, _ = w.Write([]byte(`{"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3","token_type":"bearer"}`))
				case "/user":
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, _ = fmt.Fprintf(w, `{"id":"u1","name":"user1","picture":%q}`, oauthURL+"/pic.png")
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer oauth.Close()
			oauthURL = oauth.URL

			paramsSaver := &recordingAvatarSaver{url: "http://example.com/params.png"}
			ownSaver := &recordingAvatarSaver{url: "http://example.com/own.png"}
			copts := CustomHandlerOpt{
				Endpoint:  oauth2.Endpoint{AuthURL: oauth.URL + "/authorize", TokenURL: oauth.URL + "/access_token"},
				InfoURL:   oauth.URL + "/user",
				MapUserFn: defaultMapUserFn,
			}
			if tt.own {
				copts.AvatarSaver = ownSaver
			}
			jwtService := token.NewService(token.Opts{SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
				TokenDuration: time.Hour, CookieDuration: time.Hour})
			h := NewCustom("myprov", Params{URL: loginURL, Cid: "cid", Csecret: "csecret", JwtService: jwtService,
				Issuer: "iss", AvatarSaver: paramsSaver, L: logger.NoOp}, copts)
			login.Config.Handler = http.HandlerFunc(Service{Provider: h}.Handler)
			login.Start()

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
			resp, err := client.Get(loginURL + "/login?site=remark")
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			u := token.User{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&u))
			assert.Equal(t, tt.wantURL, u.Picture)

			want, other := paramsSaver, ownSaver
			if tt.own {
				want, other = ownSaver, paramsSaver
			}
			assert.Equal(t, []string{oauth.URL + "/pic.png"}, want.saved())
			assert.Empty(t, other.saved())
		})
	}
}
