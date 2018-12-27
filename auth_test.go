package auth

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/middleware"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
)

func TestNewService(t *testing.T) {

	options := Opts{
		SecretReader:   token.SecretFunc(func(id string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-test-app",
		URL:            "http://127.0.0.1:8080",
		AvatarStore:    avatar.NewLocalFS("/tmp", 120),
	}

	_, err := NewService(options)
	assert.NoError(t, err)
}

func TestNewServiceFailed(t *testing.T) {
	_, err := NewService(Opts{})
	assert.NotNil(t, err)
}

func TestProvider(t *testing.T) {
	options := Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8080",
	}
	svc, err := NewService(options)
	assert.NoError(t, err)

	_, err = svc.Provider("some provider")
	assert.EqualError(t, err, "provider some provider not found")

	svc.AddProvider("dev", "cid", "csecret")
	svc.AddProvider("github", "cid", "csecret")
	svc.AddProvider("google", "cid", "csecret")
	svc.AddProvider("facebook", "cid", "csecret")
	svc.AddProvider("yandex", "cid", "csecret")

	p, err := svc.Provider("dev")
	assert.NoError(t, err)
	assert.Equal(t, "dev", p.Name)
	assert.Equal(t, "cid", p.Cid)
	assert.Equal(t, "csecret", p.Csecret)
	assert.Equal(t, "go-pkgz/auth", p.Issuer)

	p, err = svc.Provider("github")
	assert.NoError(t, err)
	assert.Equal(t, "github", p.Name)
}

func TestIntegrationProtected(t *testing.T) {

	teardown := prepService(t)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	resp, err := client.Get("http://127.0.0.1:8080/private")
	require.Nil(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	defer resp.Body.Close()

	// check non-admin, permanent
	resp, err = client.Get("http://127.0.0.1:8080/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)
	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 86400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	resp, err = client.Get("http://127.0.0.1:8080/private")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
}

func TestIntegrationAvatar(t *testing.T) {

	teardown := prepService(t)
	defer teardown()

	// login
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8080/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	resp, err = http.Get("http://127.0.0.1:8080/avatar/ccfa2abd01667605b4e1fc4fcb91b1e1af323240.image")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, 825, len(b))
}

func TestIntegrationList(t *testing.T) {
	teardown := prepService(t)
	defer teardown()

	resp, err := http.Get("http://127.0.0.1:8080/auth/list")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `["dev","github"]`, string(b))

}
func prepService(t *testing.T) (teardown func()) {
	options := Opts{
		SecretReader:   token.SecretFunc(func(id string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-test-app",
		URL:            "http://127.0.0.1:8080",
		DisableXSRF:    true,
		Validator: middleware.ValidatorFunc(func(_ string, claims token.Claims) bool {
			return claims.User != nil && strings.HasPrefix(claims.User.Name, "dev_") // allow only dev_ names
		}),
		AvatarStore: avatar.NewLocalFS("/tmp/auth-pkgz", 120),
	}

	svc, err := NewService(options)
	require.NoError(t, err)
	svc.AddProvider("dev", "", "")           // add dev provider
	svc.AddProvider("github", "cid", "csec") // add github provider

	// run dev/test oauth2 server on :8084
	var devAuthServer provider.DevAuthServer
	go func() {
		p, err := svc.Provider("dev")
		if err != nil {
			t.Fatal(err)
		}
		devAuthServer = provider.DevAuthServer{Provider: p, Automatic: true}
		devAuthServer.Run()
	}()

	m := svc.Middleware()
	// setup http server
	mux := http.NewServeMux()
	mux.Handle("/open", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { // no token required
		_, _ = w.Write([]byte("open route, no token needed\n"))
	}))
	mux.Handle("/private", m.Auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { // token required
		_, _ = w.Write([]byte("open route, no token needed\n"))
	})))

	// setup auth routes
	authRoute, avaRoutes := svc.Handlers()
	mux.Handle("/auth/", authRoute)                                // add token handlers
	mux.Handle("/avatar/", http.StripPrefix("/avatar", avaRoutes)) // add avatar handler

	l, err := net.Listen("tcp", "127.0.0.1:8080")
	require.Nil(t, err)
	ts := httptest.NewUnstartedServer(mux)
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()

	return func() {
		ts.Close()
		devAuthServer.Shutdown()
	}
}
