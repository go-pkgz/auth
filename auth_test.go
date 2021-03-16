package auth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
)

func TestNewService(t *testing.T) {

	options := Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-test-app",
		URL:            "http://127.0.0.1:8089",
		AvatarStore:    avatar.NewLocalFS("/tmp"),
		Logger:         logger.Std,
	}

	svc := NewService(options)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.TokenService())
	assert.NotNil(t, svc.AvatarProxy())
}

func TestProvider(t *testing.T) {
	options := Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger:       logger.Std,
	}
	svc := NewService(options)

	_, err := svc.Provider("some provider")
	assert.EqualError(t, err, "provider some provider not found")

	svc.AddProvider("dev", "cid", "csecret")
	svc.AddProvider("github", "cid", "csecret")
	svc.AddProvider("google", "cid", "csecret")
	svc.AddProvider("facebook", "cid", "csecret")
	svc.AddProvider("yandex", "cid", "csecret")
	svc.AddProvider("microsoft", "cid", "csecret")
	svc.AddProvider("battlenet", "cid", "csecret")
	svc.AddProvider("bad", "cid", "csecret")

	c := customHandler{}
	svc.AddCustomHandler(c)

	p, err := svc.Provider("dev")
	assert.NoError(t, err)
	op := p.Provider.(provider.Oauth2Handler)
	assert.Equal(t, "dev", op.Name())
	assert.Equal(t, "cid", op.Cid)
	assert.Equal(t, "csecret", op.Csecret)
	assert.Equal(t, "go-pkgz/auth", op.Issuer)

	p, err = svc.Provider("github")
	assert.NoError(t, err)
	op = p.Provider.(provider.Oauth2Handler)
	assert.Equal(t, "github", op.Name())

	pp := svc.Providers()
	assert.Equal(t, 8, len(pp))

	ch, err := svc.Provider("telegramBotMySiteCom")
	assert.NoError(t, err)
	chp := ch.Provider.(provider.Provider)
	assert.Equal(t, "telegramBotMySiteCom", chp.Name())
}

func TestIntegrationProtected(t *testing.T) {

	_, teardown := prepService(t)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	resp, err := client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, "Unauthorized\n", string(body))

	// check non-admin, permanent
	resp, err = client.Get("http://127.0.0.1:8089/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)
	require.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 86400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	resp, err = client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
}

func TestIntegrationBasicAuth(t *testing.T) {

	_, teardown := prepService(t)
	defer teardown()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "http://127.0.0.1:8089/private", nil)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", "http://127.0.0.1:8089/private", nil)
	require.Nil(t, err)
	req.SetBasicAuth("admin", "password")
	resp, err = client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
}

func TestIntegrationAvatar(t *testing.T) {

	_, teardown := prepService(t)
	defer teardown()

	// login
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8089/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	resp, err = http.Get("http://127.0.0.1:8089/api/v1/avatar/ccfa2abd01667605b4e1fc4fcb91b1e1af323240.image")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, 569, len(b))
}

func TestIntegrationList(t *testing.T) {
	_, teardown := prepService(t)
	defer teardown()

	resp, err := http.Get("http://127.0.0.1:8089/auth/list")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `["dev","github","custom123","direct","email"]`+"\n", string(b))
}

func TestIntegrationUserInfo(t *testing.T) {
	_, teardown := prepService(t)
	defer teardown()

	resp, err := http.Get("http://127.0.0.1:8089/auth/user")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode)

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// login
	resp, err = client.Get("http://127.0.0.1:8089/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()

	// get user info
	req, err := http.NewRequest("GET", "http://127.0.0.1:8089/auth/user", nil)
	require.NoError(t, err)
	t.Log(resp.Cookies())
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	u := token.User{}
	err = json.NewDecoder(resp.Body).Decode(&u)
	require.NoError(t, err)

	assert.Equal(t, token.User{Name: "dev_user", ID: "dev_user", Audience: "my-test-site",
		Picture: "http://127.0.0.1:8089/api/v1/avatar/ccfa2abd01667605b4e1fc4fcb91b1e1af323240.image"}, u)
}

func TestLogout(t *testing.T) {
	_, teardown := prepService(t)
	defer teardown()

	// login
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8089/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	// logout
	resp, err = client.Get("http://127.0.0.1:8089/auth/logout")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()

	resp, err = client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	defer resp.Body.Close()
}

func TestLogoutNoProviders(t *testing.T) {
	svc := NewService(Opts{Logger: logger.Std})
	authRoute, _ := svc.Handlers()

	mux := http.NewServeMux()
	mux.Handle("/auth/", authRoute)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/auth/logout")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 400, resp.StatusCode)
	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "{\"error\":\"provides not defined\"}\n", string(b))
}

func TestBadRequests(t *testing.T) {
	_, teardown := prepService(t)
	defer teardown()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8089/auth/bad/login")
	require.Nil(t, err)
	assert.Equal(t, 400, resp.StatusCode)
	defer resp.Body.Close()

	resp, err = client.Get("http://127.0.0.1:8089/auth")
	require.Nil(t, err)
	assert.Equal(t, 400, resp.StatusCode)
	defer resp.Body.Close()
}

func TestDirectProvider(t *testing.T) {
	_, teardown := prepService(t)
	defer teardown()

	// login
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8089/auth/direct/login?user=dev_direct&passwd=bad")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)

	resp, err = client.Get("http://127.0.0.1:8089/auth/direct/login?user=dev_direct&passwd=password")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)
	require.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 86400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	resp, err = client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
}

func TestVerifProvider(t *testing.T) {
	_, teardown := prepService(t)
	defer teardown()

	// login
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8089/auth/email/login?user=dev&address=xyz@gmail.com")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	tkn := sender.text
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client = &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err = client.Get("http://127.0.0.1:8089/auth/email/login?token=" + tkn)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)

	u := token.User{}
	err = json.Unmarshal(body, &u)
	require.NoError(t, err)
	assert.Equal(t, token.User{Name: "dev", ID: "email_84714ea398a960df03e2619d1b850dfac25f585e",
		Picture: "http://127.0.0.1:8089/api/v1/avatar/e8eb81cc51b1123059ab29575296cbfd8a6a1b6e.image"}, u)

	require.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 86400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")
}

func prepService(t *testing.T) (svc *Service, teardown func()) { //nolint unparam

	options := Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-test-app",
		URL:            "http://127.0.0.1:8089",
		DisableXSRF:    true,
		DisableIAT:     true,
		Validator: token.ValidatorFunc(func(_ string, claims token.Claims) bool {
			return claims.User != nil && strings.HasPrefix(claims.User.Name, "dev_") // allow only dev_ names
		}),
		AvatarStore:       avatar.NewLocalFS("/tmp/auth-pkgz"),
		AvatarResizeLimit: 120,
		AvatarRoutePath:   "/api/v1/avatar",
		AdminPasswd:       "password",
		Logger:            logger.Std,
	}

	svc = NewService(options)
	svc.AddDevProvider(18084)                // add dev provider on 18084
	svc.AddProvider("github", "cid", "csec") // add github provider

	// add go-oauth2/oauth2 provider
	svc.AddCustomProvider("custom123", Client{"cid", "csecret"}, provider.CustomHandlerOpt{})

	// add direct provider
	svc.AddDirectProvider("direct", provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
		return user == "dev_direct" && password == "password", nil
	}))

	svc.AddVerifProvider("email", "{{.Token}}", &sender)

	// run dev/test oauth2 server on :18084
	devAuth, err := svc.DevAuth()
	require.NoError(t, err)
	devAuth.Automatic = true // eliminate form
	go devAuth.Run(context.TODO())
	time.Sleep(time.Millisecond * 50)

	// setup http server
	m := svc.Middleware()
	mux := http.NewServeMux()
	mux.Handle("/open", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { // no token required
		_, _ = w.Write([]byte("open route, no token needed\n"))
	}))
	mux.Handle("/private", m.Auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { // token required
		_, _ = w.Write([]byte("open route, no token needed\n"))
	})))

	// setup auth routes
	authRoute, avaRoutes := svc.Handlers()
	mux.Handle("/auth/", authRoute)                                              // add token handlers
	mux.Handle("/api/v1/avatar/", http.StripPrefix("/api/v1/avatar", avaRoutes)) // add avatar handler

	l, err := net.Listen("tcp", "127.0.0.1:8089")
	require.Nil(t, err)
	ts := httptest.NewUnstartedServer(mux)
	assert.NoError(t, ts.Listener.Close())
	ts.Listener = l
	ts.Start()

	return svc, func() {
		ts.Close()
		devAuth.Shutdown()
		_ = os.RemoveAll("/tmp/auth-pkgz")
	}
}

var sender = mockSender{}

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

type customHandler struct{}

func (c customHandler) Name() string {
	return "telegramBotMySiteCom"
}
func (c customHandler) LoginHandler(w http.ResponseWriter, r *http.Request)  {}
func (c customHandler) AuthHandler(w http.ResponseWriter, r *http.Request)   {}
func (c customHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {}
