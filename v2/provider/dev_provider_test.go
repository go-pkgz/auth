package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

func TestDevProvider(t *testing.T) {
	params := Params{Cid: "cid", Csecret: "csecret", URL: "http://127.0.0.1:8080", L: logger.Std, Port: 18084,
		JwtService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
			DisableIAT:     true,
		}),
	}

	devProvider := NewDev(params)
	s := Service{Provider: devProvider}
	devOauth2Srv := DevAuthServer{Provider: devProvider, Automatic: true, username: "dev_user", L: logger.Std}
	devOauth2Srv.GetEmailFn = func(username string) string {
		return username + "@example.com"
	}

	router := http.NewServeMux()
	router.Handle("/auth/dev/", http.HandlerFunc(s.Handler))

	ts := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", 8080), Handler: router} //nolint:gosec
	go devOauth2Srv.Run(context.TODO())
	go ts.ListenAndServe()
	defer func() {
		devOauth2Srv.Shutdown()
		_ = ts.Shutdown(context.TODO())
	}()

	time.Sleep(200 * time.Millisecond)

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// check non-admin, permanent
	resp, err := client.Get("http://127.0.0.1:8080/auth/dev/login?site=my-test-site")
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

	claims, err := params.JwtService.Parse(resp.Cookies()[0].Value)
	assert.NoError(t, err)

	assert.Equal(t, token.User{Name: "dev_user", ID: "dev_user",
		Picture: "http://127.0.0.1:18084/avatar?user=dev_user", IP: "", Email: "dev_user@example.com"}, *claims.User)

	// check avatar
	resp, err = client.Get("http://127.0.0.1:18084/avatar?user=dev_user")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, 960, len(body))
	t.Logf("headers: %+v", resp.Header)
}

func TestDevProviderCancel(t *testing.T) {
	params := Params{Cid: "cid", Csecret: "csecret", URL: "http://127.0.0.1:8080", L: logger.Std,
		JwtService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
			DisableIAT:     true,
		}),
	}

	devProvider := NewDev(params)
	devOauth2Srv := DevAuthServer{Provider: devProvider, Automatic: true, username: "dev_user", L: logger.Std}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() {
		devOauth2Srv.Run(ctx)
		done <- true
	}()
	cancel()

	select {
	case <-time.After(time.Second):
		t.Fail()
	case <-done:
	}
}
