package provider

import (
	"bytes"
	"context"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/v2/logger"
	"github.com/go-pkgz/auth/v2/token"
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
	startServer(t, ts)
	go devOauth2Srv.Run(context.TODO())
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
	// the identicon is encoded by the standard library, so its byte count moves with the Go
	// release: this read 960 until Go 1.27 changed the encoder. Assert the dimensions the
	// generator promises instead, which is what the endpoint owes its caller
	avatarImg, avatarFormat, err := image.Decode(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "png", avatarFormat)
	assert.Equal(t, image.Rect(0, 0, 300, 300), avatarImg.Bounds())
	assert.False(t, uniformImage(avatarImg), "the served avatar is a single flat color")
	t.Logf("headers: %+v", resp.Header)
}

func TestDevProviderLoginForm(t *testing.T) {
	params := Params{Cid: "cid", Csecret: "csecret", URL: "http://127.0.0.1:8080", L: logger.Std, Port: 18085}
	devOauth2Srv := DevAuthServer{Provider: NewDev(params), L: logger.Std}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		devOauth2Srv.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	// without Automatic the dev server asks for a username before redirecting back
	client := &http.Client{Timeout: 5 * time.Second}
	var body []byte
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://127.0.0.1:18085/login/oauth/authorize?state=12345")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		body, err = io.ReadAll(resp.Body)
		return err == nil
	}, 2*time.Second, 50*time.Millisecond)

	page := string(body)
	assertLoginPageMarkup(t, page)
	assert.Contains(t, page, `action="/login/oauth/authorize?state=12345"`)
}

// assertLoginPageMarkup checks that a built-in login page is a standards-mode HTML document
// that declares its language and encoding, scales on phones and runs its script inside <body>
func assertLoginPageMarkup(t *testing.T, page string) {
	t.Helper()
	assert.True(t, strings.HasPrefix(page, "<!DOCTYPE html>\n"), "page must start with the doctype, or browsers render it in quirks mode")
	assert.Contains(t, page, `<html lang="en">`)
	assert.Contains(t, page, `<meta charset="utf-8">`)
	assert.Contains(t, page, `<meta name="viewport" content="width=device-width, initial-scale=1">`)
	scriptAt, bodyEndAt := strings.Index(page, "<script>"), strings.Index(page, "</body>")
	require.Positive(t, scriptAt, "page has no script")
	require.Positive(t, bodyEndAt, "page has no </body>")
	assert.Less(t, scriptAt, bodyEndAt, "script must sit inside <body>")
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
