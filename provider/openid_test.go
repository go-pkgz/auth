package provider_test

import (
	"context"
	"fmt"
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewOpenID(t *testing.T) {
	testSrvPort := 9091
	devPort := 9092

	expectedTestUserSub := fmt.Sprintf("test-user-%d", devPort)
	svc := auth.NewService(auth.Opts{
		SecretReader: token.SecretFunc(func(aud string) (string, error) {
			return "some-signing-key", nil
		}),
		Logger:      logger.Std,
		AvatarStore: avatar.NewNoOp(),
		URL:         fmt.Sprintf("http://127.0.0.1:%d", testSrvPort),
	})

	svc.AddDevOpenIDProvider(devPort)
	devAuth, err := svc.DevAuth()
	require.NoError(t, err)

	devAuth.Automatic = true
	devAuth.CustomizeIDTokenFn = func(m map[string]interface{}) map[string]interface{} {
		m["sub"] = expectedTestUserSub
		return m
	}

	go devAuth.Run(context.Background())
	defer devAuth.Shutdown()

	authHandler, _ := svc.Handlers()
	server := httptest.NewUnstartedServer(authHandler)
	server.Listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", testSrvPort))
	require.NoError(t, err)
	server.Start()

	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := http.Client{
		Jar: jar,
	}

	require.NoError(t, waitFor(fmt.Sprintf("127.0.0.1:%d", testSrvPort)))
	require.NoError(t, waitFor(fmt.Sprintf("127.0.0.1:%d", devPort)))

	resp, err := client.Get(server.URL + "/auth/dev/login")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cookies := resp.Cookies()
	var cookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "JWT" {
			cookie = c
			break
		}
	}

	require.NotNil(t, cookie)
	claims, err := devAuth.Provider.JwtService.Parse(cookie.Value)
	require.NoError(t, err)

	// check user details are from the ID token
	assert.Equal(t, expectedTestUserSub, claims.User.ID)
}

func waitFor(host string) error {
	for i := 1; i < 20; i++ {
		time.Sleep(time.Duration(i*10) * time.Millisecond)

		dial, err := net.Dial("tcp", host)
		if err == nil {
			return dial.Close()
		}
	}

	return fmt.Errorf("timeout waiting for %s", host)
}
