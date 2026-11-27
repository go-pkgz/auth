package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/v2/avatar"
	"github.com/go-pkgz/auth/v2/logger"
	"github.com/go-pkgz/auth/v2/provider"
	"github.com/go-pkgz/auth/v2/token"
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

	svc.AddProviderWithUserAttributes("dev", "cid", "csecret", provider.UserAttributes{"attrName": "attrValue"})
	svc.AddProvider("github", "cid", "csecret")
	svc.AddProvider("google", "cid", "csecret")
	svc.AddProvider("facebook", "cid", "csecret")
	svc.AddProvider("yandex", "cid", "csecret")
	svc.AddProvider("microsoft", "cid", "csecret")
	svc.AddProvider("twitter", "cid", "csecret")
	svc.AddProvider("battlenet", "cid", "csecret")
	svc.AddProvider("patreon", "cid", "csecret")
	svc.AddProvider("discord", "cid", "csecret")
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
	assert.Equal(t, provider.UserAttributes{"attrName": "attrValue"}, op.UserAttributes)

	p, err = svc.Provider("github")
	assert.NoError(t, err)
	op = p.Provider.(provider.Oauth2Handler)
	assert.Equal(t, "github", op.Name())

	pp := svc.Providers()
	assert.Equal(t, 11, len(pp))

	ch, err := svc.Provider("telegramBotMySiteCom")
	assert.NoError(t, err)
	chp := ch.Provider
	assert.Equal(t, "telegramBotMySiteCom", chp.Name())
}

func TestService_AddProviderUnknownName(t *testing.T) {
	var logged []string
	svc := NewService(Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger: logger.Func(func(format string, args ...any) {
			if msg := fmt.Sprintf(format, args...); strings.HasPrefix(msg, "[ERROR]") {
				logged = append(logged, msg)
			}
		}),
	})

	svc.AddProvider("GitHub", "cid", "csecret")
	require.Len(t, svc.Providers(), 1, "names are matched case-insensitively")
	assert.Empty(t, logged, "a known name logs no error")

	for _, name := range []string{"apple", "telegram", "gitlab", "twitter-v2"} {
		logged = nil
		svc.AddProvider(name, "cid", "csecret")
		assert.Equal(t, []string{fmt.Sprintf("[ERROR] unknown provider %q, nothing registered", name)}, logged)
	}
	assert.Len(t, svc.Providers(), 1, "an unknown name registers nothing")
}

func TestService_AddTwitterV2Provider(t *testing.T) {
	svc := NewService(Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger:       logger.Std,
	})
	svc.AddProviderWithUserAttributes("twitter_v2", "cid", "csecret", provider.UserAttributes{"username": "handle"})

	// the oauth2 provider takes the place of the oauth1 one, under the same name
	p, err := svc.Provider("twitter")
	require.NoError(t, err)
	op, ok := p.Provider.(provider.Oauth2Handler)
	require.True(t, ok, "oauth2 handler expected, got %T", p.Provider)
	assert.Equal(t, "twitter", op.Name())
	assert.Equal(t, "cid", op.Cid)
	assert.Equal(t, "csecret", op.Csecret)
	assert.Equal(t, provider.UserAttributes{"username": "handle"}, op.UserAttributes)
}

func TestService_AddMicrosoftProvider(t *testing.T) {
	options := Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger:       logger.Std,
	}

	t.Run("with custom tenant", func(t *testing.T) {
		svc := NewService(options)
		svc.AddMicrosoftProvider("cid", "csecret", "my-tenant-id")
		p, err := svc.Provider("microsoft")
		assert.NoError(t, err)
		op := p.Provider.(provider.Oauth2Handler)
		assert.Equal(t, "microsoft", op.Name())
		assert.Equal(t, "my-tenant-id", op.MicrosoftTenant)
	})

	t.Run("with empty tenant defaults to common", func(t *testing.T) {
		svc := NewService(options)
		svc.AddMicrosoftProvider("cid", "csecret", "")
		p, err := svc.Provider("microsoft")
		assert.NoError(t, err)
		op := p.Provider.(provider.Oauth2Handler)
		assert.Equal(t, "microsoft", op.Name())
	})
}

func TestService_AddGithubProviderWithNumericID(t *testing.T) {
	options := Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger:       logger.Std,
	}

	t.Run("numeric id enabled", func(t *testing.T) {
		svc := NewService(options)
		svc.AddGithubProviderWithNumericID("cid", "csecret")
		p, err := svc.Provider("github")
		assert.NoError(t, err)
		op := p.Provider.(provider.Oauth2Handler)
		assert.Equal(t, "github", op.Name())
		assert.True(t, op.GithubNumericID)
	})

	t.Run("default registration keeps login-based id", func(t *testing.T) {
		svc := NewService(options)
		svc.AddProvider("github", "cid", "csecret")
		p, err := svc.Provider("github")
		assert.NoError(t, err)
		op := p.Provider.(provider.Oauth2Handler)
		assert.Equal(t, "github", op.Name())
		assert.False(t, op.GithubNumericID)
	})
}

func TestService_AddVerifProvider_UsesCustomConfirmationStore(t *testing.T) {
	custom := &countingVerifStore{}
	svc := NewService(Opts{
		SecretReader:           token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:                    "http://127.0.0.1",
		Logger:                 logger.Std,
		VerifConfirmationStore: custom,
	})
	svc.AddVerifProvider("email", "{{.Token}}", provider.SenderFunc(func(string, string) error { return nil }))
	assert.Same(t, custom, svc.verifConfirmStore, "custom store from Opts must be used, not the in-memory default")
}

func TestService_AddVerifProvider_TypedNilStoreFuncFallsBackToDefault(t *testing.T) {
	// Opts.VerifConfirmationStore set to a typed-nil VerifConfirmationStoreFunc
	// is a non-nil interface wrapping a nil func. Without a service-level
	// guard the != nil check at AddVerifProvider succeeds, NewInMemoryVerifStore
	// is skipped, and the handler-level guard then normalizes the typed-nil to
	// nil at redemption -- net result is replay protection silently disabled.
	var nilFn provider.VerifConfirmationStoreFunc
	svc := NewService(Opts{
		SecretReader:           token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:                    "http://127.0.0.1",
		Logger:                 logger.Std,
		VerifConfirmationStore: nilFn,
	})
	svc.AddVerifProvider("email", "{{.Token}}", provider.SenderFunc(func(string, string) error { return nil }))
	require.NotNil(t, svc.verifConfirmStore, "typed-nil func must fall back to in-memory default, not silently disable protection")
	_, ok := svc.verifConfirmStore.(provider.VerifConfirmationStoreFunc)
	assert.False(t, ok, "fallback must be the in-memory default, not the typed-nil func itself")
}

func TestService_AddVerifProvider_DefaultsToInMemory(t *testing.T) {
	svc := NewService(Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1",
		Logger:       logger.Std,
	})
	svc.AddVerifProvider("email", "{{.Token}}", provider.SenderFunc(func(string, string) error { return nil }))
	require.NotNil(t, svc.verifConfirmStore, "default store must be installed when Opts.VerifConfirmationStore is nil")
	first := svc.verifConfirmStore
	svc.AddVerifProvider("email2", "{{.Token}}", provider.SenderFunc(func(string, string) error { return nil }))
	assert.Same(t, first, svc.verifConfirmStore, "subsequent AddVerifProvider calls must reuse the same store")
}

type countingVerifStore struct{ calls int }

func (s *countingVerifStore) MarkUsed(string, time.Duration) (bool, error) {
	s.calls++
	return false, nil
}

func TestService_AddAppleProvider(t *testing.T) {

	options := Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger:       logger.Std,
	}
	svc := NewService(options)

	testValidKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`
	testPrivKeyFileName := "privKeyTest.tmp"

	dir, err := os.MkdirTemp(os.TempDir(), testPrivKeyFileName)
	assert.NoError(t, err)
	assert.NotNil(t, dir)
	if err != nil {
		require.NoError(t, err)
		return
	}

	defer func() {
		err = os.RemoveAll(dir)
		require.NoError(t, err)
	}()

	filePath := filepath.Join(dir, testPrivKeyFileName)

	if err = os.WriteFile(filePath, []byte(testValidKey), 0o600); err != nil {
		require.NoError(t, err)
		return
	}
	assert.NoError(t, err)

	appleCfg := provider.AppleConfig{
		ClientID: "111222",
		TeamID:   "3334445556",
		KeyID:    "0011002200",
	}

	err = svc.AddAppleProvider(appleCfg, provider.LoadApplePrivateKeyFromFile(filePath))
	require.NoError(t, err)
	p, err := svc.Provider("apple")
	assert.NoError(t, err)
	assert.Equal(t, p.Name(), "apple")

	err = svc.AddAppleProvider(appleCfg, nil)
	require.Error(t, err)

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
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "Unauthorized\n", string(body))

	// check non-admin, permanent
	resp, err = client.Get("http://127.0.0.1:8089/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
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
	assert.NoError(t, resp.Body.Close())
}

func TestIntegrationBasicAuth(t *testing.T) {

	_, teardown := prepService(t)
	defer teardown()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "http://127.0.0.1:8089/private", http.NoBody)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", "http://127.0.0.1:8089/private", http.NoBody)
	require.Nil(t, err)
	req.SetBasicAuth("admin", "password")
	resp, err = client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.NoError(t, resp.Body.Close())
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

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// what the endpoint promises is a decodable image within the resize limit, not a byte count.
	// the encoders are the standard library's, so their output moves with the Go release: this
	// assertion read 569 bytes until Go 1.27 changed the compressor and produced 507 for the same
	// picture, failing a test that nothing had touched
	img, format, err := image.Decode(bytes.NewReader(b))
	require.NoError(t, err, "the avatar endpoint has to serve a decodable image")
	assert.Equal(t, "png", format)
	// the dev provider serves a 300x300 identicon and prepService sets AvatarResizeLimit to 120,
	// so the result is exactly 120x120. An upper bound would pass a 60x60 regression
	assert.Equal(t, image.Rect(0, 0, 120, 120), img.Bounds())
	// a blank canvas of the right size would satisfy everything above
	assert.False(t, uniformImage(img), "the served avatar is a single flat color")
}

func TestNewServiceAvatarIdenticonSize(t *testing.T) {
	svc := NewService(Opts{AvatarStore: avatar.NewNoOp(), AvatarIdenticonSize: 48})
	require.NotNil(t, svc.avatarProxy)
	assert.Equal(t, 48, svc.avatarProxy.IdenticonSize, "Opts.AvatarIdenticonSize has to reach the avatar proxy")
}

func TestAddCustomProviderAvatarSaver(t *testing.T) {
	svc := NewService(Opts{AvatarStore: avatar.NewNoOp(), URL: "http://127.0.0.1:8089"})
	saver := &customAvatarSaver{}
	svc.AddCustomProvider("own", Client{"cid", "csecret"}, provider.CustomHandlerOpt{AvatarSaver: saver})
	svc.AddCustomProvider("proxy", Client{"cid", "csecret"}, provider.CustomHandlerOpt{})

	p, err := svc.Provider("own")
	require.NoError(t, err)
	assert.Same(t, saver, p.Provider.(provider.Oauth2Handler).AvatarSaver, "the provider's own saver")

	p, err = svc.Provider("proxy")
	require.NoError(t, err)
	assert.Same(t, svc.AvatarProxy(), p.Provider.(provider.Oauth2Handler).AvatarSaver, "the service's avatar proxy")
}

type customAvatarSaver struct{}

func (customAvatarSaver) Put(token.User, *http.Client) (string, error) { return "", nil }

func TestIntegrationList(t *testing.T) {
	_, teardown := prepService(t, func(svc *Service) {
		svc.AddProvider("github", "cid", "csec")
		// add go-oauth2/oauth2 provider
		svc.AddCustomProvider("custom123", Client{"cid", "csecret"}, provider.CustomHandlerOpt{})
	})
	defer teardown()

	resp, err := http.Get("http://127.0.0.1:8089/auth/list")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `["dev","github","custom123"]`+"\n", string(b))
}

func TestIntegrationInvalidProviderNames(t *testing.T) {
	invalidNames := []string{
		"provider/with/slashes",
		"provider with spaces",
		" providerWithSpacesAround\t",
		"providerWithReserved-$-Char",
		"providerWithReserved-&-Char",
		"providerWithReserved-+-Char",
		"providerWithReserved-,-Char",
		"providerWithReserved-:-Char",
		"providerWithReserved-;-Char",
		"providerWithReserved-=-Char",
		"providerWithReserved-?-Char",
		"providerWithReserved-@-Char",
		"providerWith%2F-EscapedSequence",
		"",
	}
	svc, teardown := prepService(t, func(svc *Service) {
		for _, name := range invalidNames {
			svc.AddCustomProvider(name, Client{"cid", "csecret"}, provider.CustomHandlerOpt{})
		}
	})
	defer teardown()

	require.Equal(t, 1, len(svc.Providers()))
	require.Equal(t, "dev", svc.Providers()[0].Name())
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
	req, err := http.NewRequest("GET", "http://127.0.0.1:8089/auth/user", http.NoBody)
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
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	defer resp.Body.Close()

	resp, err = client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 401, resp.StatusCode)
	assert.NoError(t, resp.Body.Close())
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
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "{\"error\":\"providers not defined\"}\n", string(b))
}

// TestHandlers_SecurityHeaders proves the mandatory CSP + nosniff wrapper is applied
// to every response returned by Service.Handlers(), regardless of route or status.
// go-pkgz/auth has no customisable HTML rendering, so this CSP is unconditionally safe.
func TestHandlers_SecurityHeaders(t *testing.T) {
	svc := NewService(Opts{Logger: logger.Std})
	authRoute, avatarRoute := svc.Handlers()

	mux := http.NewServeMux()
	mux.Handle("/auth/", authRoute)
	mux.Handle("/avatar/", avatarRoute)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// avatar handler verified separately in avatar_test.go; here we just need to
	// confirm the wrapper applies across the auth route group.
	probes := []string{
		"/auth/list",      // 200 JSON
		"/auth/logout",    // 400 JSON (no providers configured)
		"/auth/user",      // 401 JSON (no jwt)
		"/auth/status",    // 200 JSON
		"/auth/bad/login", // 400 JSON
	}
	for _, path := range probes {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			require.NoError(t, err)
			defer resp.Body.Close()
			csp := resp.Header.Get("Content-Security-Policy")
			assert.Contains(t, csp, "default-src 'none'", "missing strict CSP on %s (status=%d)", path, resp.StatusCode)
			assert.Contains(t, csp, "sandbox", "missing sandbox directive on %s", path)
			assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"),
				"missing nosniff on %s", path)
		})
	}
}

// TestHandlers_NoAvatarStore proves the avatar route stays serviceable when no
// AvatarStore is configured: the proxy is nil in that case, so the returned
// handler must answer 404 instead of dereferencing it.
func TestHandlers_NoAvatarStore(t *testing.T) {
	svc := NewService(Opts{Logger: logger.Std})
	require.Nil(t, svc.AvatarProxy())

	_, avatarRoute := svc.Handlers()
	require.NotNil(t, avatarRoute)

	mux := http.NewServeMux()
	mux.Handle("/avatar/", avatarRoute)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/avatar/some-user.image")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
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
	assert.NoError(t, resp.Body.Close())

}

func TestDirectProvider(t *testing.T) {
	_, teardown := prepService(t, func(svc *Service) {
		svc.AddDirectProvider("direct", provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
			return user == "dev_direct" && password == "password", nil
		}))
	})
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

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)

	assert.Contains(t, string(body), `"name":"dev_direct","id":"direct_38773b45e3a477434abb6d08668358a2b0ddd2f5"`)

	require.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 86400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	resp, err = client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.NoError(t, resp.Body.Close())
}

func TestDirectProvider_WithCustomUserIDFunc(t *testing.T) {
	_, teardown := prepService(t, func(svc *Service) {
		svc.AddDirectProviderWithUserIDFunc("direct_custom",
			provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
				return user == "dev_direct" && password == "password", nil
			}),
			func(user string, r *http.Request) string {
				return "blah"
			},
		)
	})
	defer teardown()

	// login
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8089/auth/direct_custom/login?user=dev_direct&passwd=bad")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)

	resp, err = client.Get("http://127.0.0.1:8089/auth/direct_custom/login?user=dev_direct&passwd=password")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)

	assert.Contains(t, string(body), `"name":"dev_direct","id":"direct_custom_5bf1fd927dfb8679496a2e6cf00cbe50c1c87145"`)

	require.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
	assert.Equal(t, 86400, resp.Cookies()[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
	assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

	resp, err = client.Get("http://127.0.0.1:8089/private")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.NoError(t, resp.Body.Close())
}

func TestVerifProvider(t *testing.T) {
	_, teardown := prepService(t, func(svc *Service) {
		svc.AddVerifProvider("email", "{{.Token}}", &sender)
	})
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

	body, err := io.ReadAll(resp.Body)
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

func TestUserAndStatusRunAuthChecks(t *testing.T) {
	svc := NewService(Opts{
		SecretReader: token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		URL:          "http://127.0.0.1:8089",
		Logger:       logger.Std,
		Validator:    token.ValidatorFunc(func(_ string, claims token.Claims) bool { return claims.User.Name != "blocked" }),
	})
	svc.AddDirectProvider("direct", provider.CredCheckerFunc(func(string, string) (bool, error) { return true, nil }))
	authRoute, _ := svc.Handlers()

	tbl := []struct {
		name, userName, userID, provider string
		loggedIn                         bool
	}{
		{name: "accepted", userName: "alice", userID: "direct_1", provider: "direct", loggedIn: true},
		{name: "rejected by validator", userName: "blocked", userID: "direct_2", provider: "direct"},
		{name: "provider not registered", userName: "bob", userID: "gone_3", provider: "gone"},
	}

	issue := func(name, id, prov, xsrf string) string {
		tkn, err := svc.TokenService().Token(token.Claims{
			User:             &token.User{Name: name, ID: id},
			AuthProvider:     &token.AuthProvider{Name: prov},
			RegisteredClaims: jwt.RegisteredClaims{Audience: []string{"site1"}, ID: xsrf, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
		})
		require.NoError(t, err)
		return tkn
	}
	// a valid session of another user, sent as the cookie next to a rejected token in the query
	session := issue("carol", "direct_9", "direct", "xsrf-carol")

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			tkn := issue(tt.userName, tt.userID, tt.provider, "xsrf-"+tt.userName)

			// the token is the request's session cookie, as a browser sends it
			call := func(path string) *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest("GET", path, http.NoBody)
				req.AddCookie(&http.Cookie{Name: "JWT", Value: tkn})
				req.Header.Set("X-XSRF-TOKEN", "xsrf-"+tt.userName)
				authRoute.ServeHTTP(rr, req)
				return rr
			}
			expired := func(rr *httptest.ResponseRecorder) bool {
				for _, c := range rr.Result().Cookies() {
					if c.Name == "JWT" && c.MaxAge < 0 {
						return true
					}
				}
				return false
			}

			user, status := call("/auth/user"), call("/auth/status")
			if tt.loggedIn {
				assert.Equal(t, http.StatusOK, user.Code)
				u := token.User{}
				require.NoError(t, json.Unmarshal(user.Body.Bytes(), &u))
				assert.Equal(t, tt.userID, u.ID)
				assert.JSONEq(t, `{"status":"logged in","user":"alice"}`, status.Body.String())
				return
			}
			assert.Equal(t, http.StatusUnauthorized, user.Code)
			assert.JSONEq(t, `{"error":"unauthorized"}`, user.Body.String())
			assert.Equal(t, http.StatusOK, status.Code)
			assert.JSONEq(t, `{"status":"not logged in"}`, status.Body.String())
			assert.True(t, expired(user), "the rejected token cookie is cleared by /auth/user")
			assert.True(t, expired(status), "the rejected token cookie is cleared by /auth/status")

			// the rejected token in the query next to another user's session cookie: refused, and that
			// session's cookies stay
			for _, tc := range []struct{ path, body string }{
				{path: "/auth/user", body: `{"error":"unauthorized"}`},
				{path: "/auth/status", body: `{"status":"not logged in"}`},
			} {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest("GET", tc.path+"?token="+tkn, http.NoBody)
				req.AddCookie(&http.Cookie{Name: "JWT", Value: session})
				req.Header.Set("X-XSRF-TOKEN", "xsrf-carol")
				authRoute.ServeHTTP(rr, req)
				wantCode := http.StatusOK
				if tc.path == "/auth/user" {
					wantCode = http.StatusUnauthorized
				}
				assert.Equal(t, wantCode, rr.Code, tc.path)
				assert.JSONEq(t, tc.body, rr.Body.String(), tc.path)
				assert.Empty(t, rr.Result().Header.Values("Set-Cookie"), "%s must leave the session cookie alone", tc.path)
			}

			// a user put into the request by a middleware in front of the routes does not count
			for _, path := range []string{"/auth/user", "/auth/status"} {
				rr := httptest.NewRecorder()
				req := token.SetUserInfo(httptest.NewRequest("GET", path, http.NoBody), token.User{ID: "outer", Name: "outer"})
				req.Header.Set("X-JWT", tkn)
				authRoute.ServeHTTP(rr, req)
				assert.NotContains(t, rr.Body.String(), "outer", path)
			}
		})
	}
}

func TestUserAndStatusBasicAuthAndRefresh(t *testing.T) {
	newSvc := func(opts Opts) (*Service, http.Handler) {
		opts.SecretReader = token.SecretFunc(func(string) (string, error) { return "secret", nil })
		opts.URL = "http://127.0.0.1:8089"
		opts.Logger = logger.Std
		svc := NewService(opts)
		svc.AddDirectProvider("direct", provider.CredCheckerFunc(func(string, string) (bool, error) { return true, nil }))
		authRoute, _ := svc.Handlers()
		return svc, authRoute
	}
	issue := func(t *testing.T, svc *Service, exp time.Time) string {
		t.Helper()
		xsrf := "xsrf-alice"
		tkn, err := svc.TokenService().Token(token.Claims{
			User:             &token.User{Name: "alice", ID: "direct_1"},
			AuthProvider:     &token.AuthProvider{Name: "direct"},
			RegisteredClaims: jwt.RegisteredClaims{Audience: []string{"site1"}, ID: xsrf, ExpiresAt: jwt.NewNumericDate(exp)},
		})
		require.NoError(t, err)
		return tkn
	}
	call := func(h http.Handler, path, cookie string, basic func(r *http.Request)) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, http.NoBody)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: cookie})
		req.Header.Set("X-XSRF-TOKEN", "xsrf-alice")
		if basic != nil {
			basic(req)
		}
		h.ServeHTTP(rr, req)
		return rr
	}

	// a basic auth identity is checked before the token, so it wins over a valid session cookie
	t.Run("admin password", func(t *testing.T) {
		svc, h := newSvc(Opts{AdminPasswd: "admin-pw"})
		session := issue(t, svc, time.Now().Add(time.Hour))
		basic := func(r *http.Request) { r.SetBasicAuth("admin", "admin-pw") }
		user := call(h, "/auth/user", session, basic)
		assert.Equal(t, http.StatusOK, user.Code)
		u := token.User{}
		require.NoError(t, json.Unmarshal(user.Body.Bytes(), &u))
		assert.Equal(t, "admin", u.ID)
		assert.JSONEq(t, `{"status":"logged in","user":"admin"}`, call(h, "/auth/status", session, basic).Body.String())
	})

	t.Run("basic auth checker", func(t *testing.T) {
		checker := func(user, passwd string) (bool, token.User, error) {
			return user == "dave" && passwd == "dave-pw", token.User{ID: "basic_dave", Name: "dave"}, nil
		}
		svc, h := newSvc(Opts{BasicAuthChecker: checker})
		session := issue(t, svc, time.Now().Add(time.Hour))
		basic := func(r *http.Request) { r.SetBasicAuth("dave", "dave-pw") }
		user := call(h, "/auth/user", session, basic)
		assert.Equal(t, http.StatusOK, user.Code)
		u := token.User{}
		require.NoError(t, json.Unmarshal(user.Body.Bytes(), &u))
		assert.Equal(t, "basic_dave", u.ID)
		assert.JSONEq(t, `{"status":"logged in","user":"dave"}`, call(h, "/auth/status", session, basic).Body.String())
	})

	// an expired session cookie is refreshed, as on any route behind Auth
	t.Run("expired session cookie", func(t *testing.T) {
		svc, h := newSvc(Opts{})
		expired := issue(t, svc, time.Now().Add(-time.Hour))
		for _, path := range []string{"/auth/user", "/auth/status"} {
			rr := call(h, path, expired, nil)
			assert.Equal(t, http.StatusOK, rr.Code, path)
			assert.Contains(t, rr.Body.String(), "alice", path)
			fresh := map[string]bool{}
			for _, c := range rr.Result().Cookies() {
				fresh[c.Name] = c.MaxAge > 0 && c.Value != "" && c.Value != expired
				if c.Name == "JWT" {
					claims, err := svc.TokenService().Parse(c.Value)
					require.NoError(t, err)
					assert.True(t, claims.ExpiresAt.After(time.Now()), "%s: the new token is not expired", path)
				}
			}
			assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, fresh, path)
		}
	})
}

func TestStatus(t *testing.T) {

	svc, teardown := prepService(t)
	defer teardown()

	authRoute, _ := svc.Handlers()

	mux := http.NewServeMux()
	mux.Handle("/auth/", authRoute)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/auth/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "{\"status\":\"not logged in\"}\n", string(b))

	// login
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err = client.Get("http://127.0.0.1:8089/auth/dev/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	resp, err = client.Get(ts.URL + "/auth/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "{\"status\":\"logged in\",\"user\":\"dev_user\"}\n", string(b))

}

func TestDevAuthServerWithoutDevProvider(t *testing.T) {
	svc := NewService(Opts{})
	assert.NotNil(t, svc)

	_, err := svc.DevAuth()
	require.NotNil(t, err)
	assert.EqualError(t, err, "dev provider not registered: provider dev not found")
}

func prepService(t *testing.T, providerConfigFunctions ...func(svc *Service)) (svc *Service, teardown func()) { //nolint unparam

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

	svc.AddDevProvider("localhost", 18084) // add dev provider on 18084

	for _, f := range providerConfigFunctions {
		f(svc)
	}

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
		_, _ = w.Write([]byte("protected route, authenticated with token\n"))
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
func (c customHandler) LoginHandler(http.ResponseWriter, *http.Request)  {}
func (c customHandler) AuthHandler(http.ResponseWriter, *http.Request)   {}
func (c customHandler) LogoutHandler(http.ResponseWriter, *http.Request) {}

// uniformImage reports whether every pixel is the same color, which is what a generator that
// stopped drawing produces: an image of exactly the right size carrying nothing
func uniformImage(img image.Image) bool {
	b := img.Bounds()
	first := img.At(b.Min.X, b.Min.Y)
	fr, fg, fb, fa := first.RGBA()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if r != fr || g != fg || bl != fb || a != fa {
				return false
			}
		}
	}
	return true
}

func TestNewService_PassesCookieOptionsToTokenService(t *testing.T) {
	// the token.Opts literal in NewService has silently dropped a field twice, bd39e5e3 for
	// SameSite and 59656e46 for XSRFIgnoreMethods, both in diffs shaped like this one: a
	// re-indent plus one added key. Nothing failed either time, because nothing asserted the
	// plumbing rather than the behavior
	svc := NewService(Opts{
		PartitionedCookies: true,
		SecureCookies:      true,
		SameSiteCookie:     http.SameSiteNoneMode,
	})

	ts := svc.TokenService()
	assert.True(t, ts.PartitionedCookies, "PartitionedCookies did not reach the token service")
	assert.True(t, ts.SecureCookies, "SecureCookies did not reach the token service")
	assert.Equal(t, http.SameSiteNoneMode, ts.SameSite, "SameSite did not reach the token service")
}

func TestNewService_WarnsOnPartitionedWithoutSecure(t *testing.T) {
	// http.SetCookie writes through String and never calls Valid, so this pairing produces a
	// header the browser silently drops with no error anywhere. The warning is the only signal
	var logged []string
	capture := logger.Func(func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	NewService(Opts{PartitionedCookies: true, SecureCookies: false, Logger: capture})
	assert.Condition(t, func() bool {
		for _, l := range logged {
			if strings.Contains(l, "PartitionedCookies requires SecureCookies") {
				return true
			}
		}
		return false
	}, "no warning for Partitioned without Secure, logged: %v", logged)

	logged = nil
	NewService(Opts{PartitionedCookies: true, SecureCookies: true, Logger: capture})
	for _, l := range logged {
		assert.NotContains(t, l, "PartitionedCookies requires SecureCookies",
			"warned about a correctly configured pairing")
	}
}
