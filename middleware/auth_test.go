package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
)

var testJwtValid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJwcm92aWRlcjFfaWQxIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9waWMucG5nIiwiaXAiOiIxMjcuMC4wLjEiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwiYXR0cnMiOnsiYm9vbGEiOnRydWUsInN0cmEiOiJzdHJhLXZhbCJ9fX0.orBYt_pVA4uvCCw0JMQLla3DA0mpjRTl_U9vT_wtI30"

var testJwtValidWrongProvider = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJwcm92aWRlcjNfaWQxIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9waWMucG5nIiwiaXAiOiIxMjcuMC4wLjEiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwiYXR0cnMiOnsiYm9vbGEiOnRydWUsInN0cmEiOiJzdHJhLXZhbCJ9fX0.p0w7GmXKwujm0ROn0RIACnBwN4KmPcqXDMS9YoFq4jQ"

var testJwtExpired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6MTE4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJwcm92aWRlcjFfaWQxIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9waWMucG5nIiwiaXAiOiIxMjcuMC4wLjEiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwiYXR0cnMiOnsiYm9vbGEiOnRydWUsInN0cmEiOiJzdHJhLXZhbCJ9fX0.PlRRc5YA6pvoVOT4NLLOoTwU2Kn3GaTfbjr6j-P6RhA"

var testJwtWithHandshake = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0._2X1cAEoxjLA7XuN8xW8V9r7rYfP_m9lSRz_9_UFzac"

var testJwtNoUser = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI3ODkxOTE4MjIsImp0aSI6InJhbmRvbSBpZCIsImlzcyI6InJlbWFyazQyIiwibmJmIjoxNTI2ODg0MjIyfQ.sBpblkbBRzZsBSPPNrTWqA5h7h54solrw5L4IypJT_o"

var testJwtWithRole = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJwcm92aWRlcjFfaWQxIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9waWMucG5nIiwiaXAiOiIxMjcuMC4wLjEiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwiYXR0cnMiOnsiYm9vbGEiOnRydWUsInN0cmEiOiJzdHJhLXZhbCJ9LCJyb2xlIjoiZW1wbG95ZWUifX0.o95raB0aNl2TWUs43Tu6xyX5Y3Fa5wv6_6RFJuN-d6g"

var testJwtValidWithAuthProvider = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJwcm92aWRlcjFfaWQxIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9waWMucG5nIiwiaXAiOiIxMjcuMC4wLjEiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwiYXR0cnMiOnsiYm9vbGEiOnRydWUsInN0cmEiOiJzdHJhLXZhbCJ9fSwiYXV0aF9wcm92aWRlciI6eyJuYW1lIjoicHJvdmlkZXIxIn19.iBKM9-lgejJNjcs-crj6gkEejnIJpavmaq8alenf0JA"

func TestAuthJWTCookie(t *testing.T) {
	a := makeTestAuth(t)

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		assert.NoError(t, err)
		assert.Equal(t, token.User{Name: "name1", ID: "provider1_id1", Picture: "http://example.com/pic.png",
			IP: "127.0.0.1", Email: "me@example.com", Audience: "test_sys",
			Attributes: map[string]any{"boola": true, "stra": "stra-val"}}, u)
		w.WriteHeader(201)
	}
	mux.Handle("/auth", a.Auth(http.HandlerFunc(handler)))
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint

	makeRequest := func(jwtCookie string, xsrfToken string) *http.Response {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.AddCookie(&http.Cookie{
			Name:     "JWT",
			Value:    jwtCookie,
			HttpOnly: true,
			Path:     "/",
			MaxAge:   expiration,
			Secure:   false,
		})
		req.Header.Add("X-XSRF-TOKEN", xsrfToken)

		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("valid token", func(t *testing.T) {
		resp := makeRequest(testJwtValid, "random id")
		assert.Equal(t, 201, resp.StatusCode, "valid token user")
	})

	t.Run("valid token with auth_provider", func(t *testing.T) {
		resp := makeRequest(testJwtValidWithAuthProvider, "random id")
		assert.Equal(t, 201, resp.StatusCode, "valid token user")
	})

	t.Run("valid token, wrong provider", func(t *testing.T) {
		resp := makeRequest(testJwtValidWrongProvider, "random id")
		assert.Equal(t, 401, resp.StatusCode, "user name1/provider3_id1 provider is not allowed")
	})

	t.Run("xsrf mismatch", func(t *testing.T) {
		resp := makeRequest(testJwtValid, "wrong id")
		assert.Equal(t, 401, resp.StatusCode, "xsrf mismatch")
	})

	t.Run("token expired and refreshed", func(t *testing.T) {
		resp := makeRequest(testJwtExpired, "random id")
		assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")
	})

	t.Run("no user info in the token", func(t *testing.T) {
		resp := makeRequest(testJwtNoUser, "random id")
		assert.Equal(t, 401, resp.StatusCode, "no user info in the token")
	})
}

func TestAuthJWTHeader(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	t.Run("valid token", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.Header.Add("X-JWT", testJwtValid)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 201, resp.StatusCode, "valid token user")
	})

	t.Run("valid token, wrong provider", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.Header.Add("X-JWT", testJwtValidWrongProvider)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode, "wrong provider")
	})

	t.Run("token expired", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.Header.Add("X-JWT", testJwtExpired)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode, "token expired")
	})
}

func TestAuthJWTRefresh(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)

	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")

	cookies := resp.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	t.Log(resp.Cookies()[0].Value)
	assert.True(t, resp.Cookies()[0].Value != testJwtExpired, "jwt token changed")

	claims, err := a.JWTService.Parse(resp.Cookies()[0].Value)
	assert.NoError(t, err)
	ts := time.Unix(claims.ExpiresAt, 0)
	assert.True(t, ts.After(time.Now()), "expiration in the future")
	log.Print(time.Unix(claims.ExpiresAt, 0))
}

func TestAuthJWTRefreshConcurrentWithCache(t *testing.T) {

	a := makeTestAuth(t)
	a.JWTService.(*token.Service).TokenDuration = time.Minute
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	var refreshCount atomic.Int32
	a.RefreshCache = newTestRefreshCache()
	sendExpired := func() {
		jar, err := cookiejar.New(nil)
		require.Nil(t, err)
		client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.NoError(t, err)

		expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/",
			MaxAge: expiration, Secure: false})
		req.Header.Add("X-XSRF-TOKEN", "random id")

		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 201, resp.StatusCode)

		cookies := resp.Cookies()
		if len(cookies) == 2 && resp.Cookies()[0].Name == "JWT" && resp.Cookies()[0].Value != testJwtExpired {
			refreshCount.Add(1)
		}
	}

	// the middleware does not dedupe simultaneous refreshes, so one request fills the cache first
	sendExpired()
	var wg sync.WaitGroup
	wg.Add(99)
	for range 99 {
		go func() {
			defer wg.Done()
			sendExpired()
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), a.RefreshCache.(*testRefreshCache).misses, "1 cache miss")
	assert.Equal(t, int32(99), a.RefreshCache.(*testRefreshCache).hits, "99 cache hits")
	assert.Equal(t, int32(1), refreshCount.Load(), "should make one refresh only")

	// make another expired token
	c, err := a.JWTService.Parse(testJwtExpired)
	require.NoError(t, err)
	c.User.ID = "provider1_other ID"
	tkSvc := a.JWTService.(*token.Service)
	tkn, err := tkSvc.Token(c)
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req.AddCookie(&http.Cookie{Name: "JWT", Value: tkn, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode)

	cookies := resp.Cookies()
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name)
	assert.NotEqual(t, tkn, resp.Cookies()[0].Value)
	t.Log(resp.Cookies()[0].Value)
}

func TestAuthRefreshCacheIsolatesUsers(t *testing.T) {
	var updates atomic.Int32
	a := makeTestAuth(t)
	a.JWTService = token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Minute,
		CookieDuration: time.Hour,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			updates.Add(1)
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})
	cache := newTestRefreshCache()
	a.RefreshCache = cache
	a.Validator = token.ValidatorFunc(func(_ string, claims token.Claims) bool { return claims.User.BoolAttr("boola") })

	entered, release := make(chan struct{}, 3), make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	upd := UserUpdFunc(func(u token.User) token.User {
		entered <- struct{}{}
		<-release
		u.SetStrAttr("req", "value")
		return u
	})
	handler := a.Auth(a.UpdateUser(upd)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})))
	server := httptest.NewServer(handler)
	defer server.Close()
	defer releaseAll()

	statuses := make(chan int, 3)
	send := func() {
		req, err := http.NewRequest("GET", server.URL, http.NoBody)
		if err != nil {
			statuses <- 0
			return
		}
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired})
		req.Header.Add("X-XSRF-TOKEN", "random id")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			statuses <- 0
			return
		}
		_ = resp.Body.Close()
		statuses <- resp.StatusCode
	}
	waitEntered := func() {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "request did not reach the user updater")
		}
	}

	go send()
	waitEntered()
	go send()
	go send()
	waitEntered()
	waitEntered()
	releaseAll()
	for range 3 {
		assert.Equal(t, http.StatusCreated, <-statuses)
	}
	assert.Equal(t, int32(1), updates.Load())
	assert.Equal(t, int32(1), atomic.LoadInt32(&cache.misses))
	assert.Equal(t, int32(2), atomic.LoadInt32(&cache.hits))
	cache.RLock()
	stored := cache.data[testJwtExpired].(token.Claims)
	cache.RUnlock()
	assert.NotContains(t, stored.User.Attributes, "req")
}

func TestAuthRefreshCacheExpiredEntry(t *testing.T) {
	var updates atomic.Int32
	j := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Minute,
		CookieDuration: time.Hour,
		SendJWTHeader:  true,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			updates.Add(1)
			claims.User.SetBoolAttr("blocked", true)
			return claims
		}),
	})
	a := makeTestAuth(t)
	a.JWTService = j
	a.Validator = token.ValidatorFunc(func(_ string, claims token.Claims) bool { return !claims.User.BoolAttr("blocked") })
	stale, err := j.Parse(testJwtExpired)
	require.NoError(t, err)
	require.True(t, j.IsExpired(stale))
	cache := newTestRefreshCache()
	cache.Set(testJwtExpired, stale)
	a.RefreshCache = cache
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, int32(1), updates.Load())
	assert.Empty(t, resp.Header.Get("X-JWT"))
	reset := map[string]bool{}
	for _, c := range resp.Cookies() {
		assert.Empty(t, c.Value, c.Name)
		assert.Negative(t, c.MaxAge, c.Name)
		reset[c.Name] = true
	}
	assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, reset)
}

func TestAuthRefreshCacheUnreadableEntry(t *testing.T) {
	a := makeTestAuth(t)
	cached, err := a.JWTService.(*token.Service).Parse(testJwtExpired)
	require.NoError(t, err)
	cached.ExpiresAt = time.Now().Add(time.Hour).Unix()
	cached.User.Attributes = map[string]any{"ch": make(chan int)}
	cache := newTestRefreshCache()
	cache.Set(testJwtExpired, cached)
	a.RefreshCache = cache
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, int32(1), atomic.LoadInt32(&cache.hits))
	reset := map[string]bool{}
	for _, c := range resp.Cookies() {
		assert.Empty(t, c.Value, c.Name)
		assert.Negative(t, c.MaxAge, c.Name)
		reset[c.Name] = true
	}
	assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, reset)
}

// TestAuthRefreshValidatesRefreshedClaims covers a block that ClaimsUpd adds when an expired token is
// refreshed. testJwtExpired is signed directly and carries no block, so only the refreshed claims have
// it: the request is refused, the client gets no fresh token, and a cached refresh is checked as well.
func TestAuthRefreshValidatesRefreshedClaims(t *testing.T) {
	blockInPlace := token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
		claims.User.SetBoolAttr("blocked", true)
		return claims
	})
	blockOnCopy := token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
		u := *claims.User
		u.Attributes = map[string]any{"blocked": true}
		claims.User = &u
		return claims
	})
	notBlocked := token.ValidatorFunc(func(_ string, claims token.Claims) bool { return !claims.User.BoolAttr("blocked") })

	tbl := []struct {
		name      string
		claimsUpd token.ClaimsUpdater
		cached    bool
	}{
		{name: "updater changes the user in place", claimsUpd: blockInPlace},
		{name: "updater replaces the user", claimsUpd: blockOnCopy},
		{name: "blocked claims in the refresh cache", cached: true},
	}

	for _, tt := range tbl {
		for _, required := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, required=%v", tt.name, required), func(t *testing.T) {
				a := makeTestAuth(t)
				a.JWTService = token.NewService(token.Opts{
					SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
					TokenDuration:  time.Second,
					CookieDuration: time.Hour * 24 * 31,
					SendJWTHeader:  true,
					ClaimsUpd:      tt.claimsUpd,
				})
				a.Validator = notBlocked
				cache := newTestRefreshCache()
				a.RefreshCache = cache
				if tt.cached {
					c, err := a.JWTService.Parse(testJwtExpired)
					require.NoError(t, err)
					c.User.SetBoolAttr("blocked", true)
					c.ExpiresAt = time.Now().Add(time.Hour).Unix()
					cache.Set(testJwtExpired, c)
				}

				var served atomic.Int32
				var servedUser atomic.Bool
				server := httptest.NewServer(a.auth(required)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					served.Add(1)
					_, err := token.GetUserInfo(r)
					servedUser.Store(err == nil)
					w.WriteHeader(http.StatusCreated)
				})))
				defer server.Close()

				for i := range 2 { // the second request repeats the first with the same expired token
					req, err := http.NewRequest("GET", server.URL, http.NoBody)
					require.NoError(t, err)
					req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
					req.Header.Add("X-XSRF-TOKEN", "random id")
					resp, err := server.Client().Do(req)
					require.NoError(t, err)
					require.NoError(t, resp.Body.Close())

					if required {
						assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "request %d", i)
					} else {
						assert.Equal(t, http.StatusCreated, resp.StatusCode, "request %d", i)
						assert.False(t, servedUser.Load(), "request %d served with a user", i)
					}
					assert.Empty(t, resp.Header.Get("X-JWT"), "request %d got a fresh token in the header", i)
					expired := map[string]bool{}
					for _, c := range resp.Cookies() {
						assert.Empty(t, c.Value, "request %d got a fresh %s cookie", i, c.Name)
						expired[c.Name] = c.MaxAge < 0 && c.Value == ""
					}
					assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, expired, "request %d", i)
				}
				if required {
					assert.Zero(t, served.Load(), "handler reached for a blocked user")
				}
			})
		}
	}
}

// TestAuthRefreshServesSignedClaims checks that a refreshed request carries the user the new token was
// signed with, also when ClaimsUpd replaces the user, and that the XSRF cookie matches that token.
func TestAuthRefreshServesSignedClaims(t *testing.T) {
	a := makeTestAuth(t)
	a.JWTService = token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Second,
		CookieDuration: time.Hour * 24 * 31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			claims.User = &token.User{ID: claims.User.ID, Name: claims.User.Name, Attributes: map[string]any{"updated": true}}
			claims.Id = "updated id"
			return claims
		}),
	})
	var updated atomic.Bool
	var audience atomic.Value
	server := httptest.NewServer(a.Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		updated.Store(err == nil && u.BoolAttr("updated"))
		audience.Store(u.Audience)
		w.WriteHeader(http.StatusCreated)
	})))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, updated.Load(), "request served with the claims before ClaimsUpd")
	assert.Equal(t, "test_sys", audience.Load(), "user audience is filled from the token, as for a token read by Get")

	cookies := map[string]string{}
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c.Value
	}
	claims, err := a.JWTService.Parse(cookies["JWT"])
	require.NoError(t, err)
	assert.Equal(t, "updated id", claims.Id)
	assert.Equal(t, claims.Id, cookies["XSRF-TOKEN"], "XSRF cookie must match the signed token")
}

// TestAuthRefreshValidatesDecodedClaims checks that the Validator and the handler see the refreshed claims with
// the types a later request reads from the token, not the Go types ClaimsUpd put in.
func TestAuthRefreshValidatesDecodedClaims(t *testing.T) {
	a := makeTestAuth(t)
	a.JWTService = token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Second,
		CookieDuration: time.Hour * 24 * 31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			claims.User.SetSliceAttr("groups", []string{"g1"})
			claims.User.Attributes["level"] = 1
			claims.User.Attributes["ext"] = json.Number("5") // a number decoded elsewhere with UseNumber
			return claims
		}),
	})
	// testJwtExpired carries no level and no groups, so the check of the token as sent passes
	a.Validator = token.ValidatorFunc(func(_ string, claims token.Claims) bool {
		if _, ok := claims.User.Attributes["level"]; !ok {
			return true
		}
		_, isNumber := claims.User.Attributes["level"].(float64)
		_, isExtNumber := claims.User.Attributes["ext"].(float64)
		_, isList := claims.User.Attributes["groups"].([]any)
		return isNumber && isExtNumber && isList
	})
	var level atomic.Value
	server := httptest.NewServer(a.Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		if err == nil {
			level.Store(fmt.Sprintf("%T", u.Attributes["level"]))
		}
		w.WriteHeader(http.StatusCreated)
	})))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "refreshed claims refused")
	assert.Equal(t, "float64", level.Load())
}

// TestAuthRefreshKeepsJSONNumber uses a TokenService whose Get reads numbers as json.Number. The refreshed
// claims keep them so, with every digit, as the next request reads them from the token.
func TestAuthRefreshKeepsJSONNumber(t *testing.T) {
	a := makeTestAuth(t)
	svc := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Second,
		CookieDuration: time.Hour * 24 * 31,
	})
	a.JWTService = numberTokenService{Service: svc}
	claims, err := svc.Parse(testJwtExpired)
	require.NoError(t, err)
	claims.User.Attributes["uid"] = json.Number("9007199254740993") // above 2^53, float64 drops the last digit
	tkn, err := svc.Token(claims)
	require.NoError(t, err)

	a.Validator = token.ValidatorFunc(func(_ string, claims token.Claims) bool {
		return claims.User.Attributes["uid"] == json.Number("9007199254740993")
	})
	var uid atomic.Value
	server := httptest.NewServer(a.Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, uErr := token.GetUserInfo(r)
		if uErr == nil {
			uid.Store(fmt.Sprintf("%T %v", u.Attributes["uid"], u.Attributes["uid"]))
		}
		w.WriteHeader(http.StatusCreated)
	})))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: tkn, HttpOnly: true, Path: "/"})
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "refreshed claims refused")
	assert.Equal(t, "json.Number 9007199254740993", uid.Load())
	assert.NotEmpty(t, resp.Header.Get("Set-Cookie"), "the token was refreshed")
}

func TestHasNumber(t *testing.T) {
	tbl := []struct {
		name   string
		claims token.Claims
		want   bool
	}{
		{name: "no user", claims: token.Claims{}},
		{name: "no number", claims: token.Claims{User: &token.User{Attributes: map[string]any{"a": 1.0, "b": []any{"x"}}}}},
		{name: "number", claims: token.Claims{User: &token.User{Attributes: map[string]any{"a": json.Number("1")}}}, want: true},
		{name: "in a list", claims: token.Claims{User: &token.User{Attributes: map[string]any{"a": []any{"x", json.Number("1")}}}},
			want: true},
		{name: "in a map", claims: token.Claims{User: &token.User{Attributes: map[string]any{"a": map[string]any{"b": json.Number("1")}}}},
			want: true},
	}
	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasNumber(tt.claims))
		})
	}
}

// numberTokenService reads the claims of the JWT cookie with json.Number for numbers, as a TokenService
// parsing with jwt's UseJSONNumber does. It skips the signature and XSRF checks, which the test does not need
type numberTokenService struct{ *token.Service }

func (s numberTokenService) Get(r *http.Request) (token.Claims, string, error) {
	cookie, err := r.Cookie("JWT")
	if err != nil {
		return token.Claims{}, "", err
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return token.Claims{}, "", errors.New("not a jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return token.Claims{}, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	claims := token.Claims{}
	if err = dec.Decode(&claims); err != nil {
		return token.Claims{}, "", err
	}
	return claims, cookie.Value, nil
}

// TestAuthRefreshNested runs the auth checks twice for one request, as Auth in front of AdminOnly does. Both
// passes refresh the same expired cookie; the response carries one JWT header, as when Set wrote it directly.
func TestAuthRefreshNested(t *testing.T) {
	a := makeTestAuth(t)
	a.JWTService = token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Second,
		CookieDuration: time.Hour * 24 * 31,
		SendJWTHeader:  true,
	})
	server := httptest.NewServer(a.Auth(a.Auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Len(t, resp.Header.Values("X-JWT"), 1)
}

// TestAuthRefreshWithoutUser covers a ClaimsUpd that drops the user of a refreshed token: the request gets
// no user and no fresh token, and the middleware does not panic.
func TestAuthRefreshWithoutUser(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(fmt.Sprintf("required=%v", required), func(t *testing.T) {
			a := makeTestAuth(t)
			a.JWTService = token.NewService(token.Opts{
				SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
				TokenDuration:  time.Second,
				CookieDuration: time.Hour * 24 * 31,
				ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
					claims.User = nil
					return claims
				}),
			})
			a.RefreshCache = newTestRefreshCache()
			var servedUser atomic.Bool
			server := httptest.NewServer(a.auth(required)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := token.GetUserInfo(r)
				servedUser.Store(err == nil)
				w.WriteHeader(http.StatusCreated)
			})))
			defer server.Close()

			req, err := http.NewRequest("GET", server.URL, http.NoBody)
			require.NoError(t, err)
			req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
			req.Header.Add("X-XSRF-TOKEN", "random id")
			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			if required {
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			} else {
				assert.Equal(t, http.StatusCreated, resp.StatusCode)
				assert.False(t, servedUser.Load())
			}
			for _, c := range resp.Cookies() {
				assert.Empty(t, c.Value, "fresh %s cookie", c.Name)
			}
		})
	}
}

// bodyJwtService writes a status and a body in Set, which a refresh must not pass on to the response
type bodyJwtService struct {
	*token.Service
}

func (b *bodyJwtService) Set(w http.ResponseWriter, claims token.Claims) (token.Claims, error) {
	w.Header().Add("Vary", "Cookie")
	w.Header().Del("X-Drop")
	w.WriteHeader(http.StatusTeapot)
	_, _ = w.Write([]byte("from Set"))
	return b.Service.Set(w, claims)
}

func TestAuthRefreshPassesOnlySetHeaders(t *testing.T) {
	a := makeTestAuth(t)
	a.JWTService = &bodyJwtService{Service: a.JWTService.(*token.Service)}
	mux := makeTestMux(t, &a, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Origin") // as a middleware in front of Auth would
		w.Header().Set("X-Drop", "1")
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusCreated, resp.StatusCode, "status comes from the handler")
	assert.Empty(t, string(body), "body comes from the handler")
	cookies := map[string]string{}
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c.Value
	}
	assert.NotEmpty(t, cookies["JWT"], "refreshed token cookie")
	assert.NotEmpty(t, cookies["XSRF-TOKEN"], "refreshed XSRF cookie")
	assert.Equal(t, []string{"Origin", "Cookie"}, resp.Header.Values("Vary"), "Set adds to the live headers")
	assert.Empty(t, resp.Header.Get("X-Drop"), "Set deletes from the live headers")
}

type badJwtService struct {
	*token.Service
}

func (b *badJwtService) Set(http.ResponseWriter, token.Claims) (token.Claims, error) {
	return token.Claims{}, fmt.Errorf("jwt set fake error")
}

func TestAuthJWTRefreshFailed(t *testing.T) {

	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	a.JWTService = &badJwtService{Service: a.JWTService.(*token.Service)}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)

	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/",
		MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	require.Nil(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Unauthorized\n", string(data))
}

func TestAuthJWtBlocked(t *testing.T) {
	a := makeTestAuth(t)
	a.Validator = token.ValidatorFunc(func(token string, claims token.Claims) bool { return false })
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "blocked user")
}

func TestAuthRejectionClearsCookies(t *testing.T) {
	tbl := []struct {
		name      string
		validator token.Validator
		jwt       string
	}{
		{name: "blocked by validator", jwt: testJwtValid,
			validator: token.ValidatorFunc(func(string, token.Claims) bool { return false })},
		{name: "provider not allowed", jwt: testJwtValidWrongProvider},
	}

	for _, tt := range tbl {
		for _, required := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, required=%v", tt.name, required), func(t *testing.T) {
				a := makeTestAuth(t)
				if tt.validator != nil {
					a.Validator = tt.validator
				}
				server := httptest.NewServer(makeTestMux(t, &a, required))
				defer server.Close()

				req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
				require.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "JWT", Value: tt.jwt, HttpOnly: true, Path: "/"})
				req.Header.Add("X-XSRF-TOKEN", "random id")
				resp, err := server.Client().Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				if required {
					assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
				} else {
					assert.Equal(t, http.StatusCreated, resp.StatusCode)
				}

				// the cookies must be in the response the client received, not added after it was written
				expired := map[string]bool{}
				for _, c := range resp.Cookies() {
					expired[c.Name] = c.MaxAge < 0 && c.Value == ""
				}
				assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, expired)
			})
		}
	}
}

func TestAuthRejectionKeepsCookiesOfAnotherToken(t *testing.T) {
	branches := []struct {
		name      string
		rejected  string // token the middleware rejects
		session   string // valid session cookie of the request
		validator token.Validator
	}{
		{name: "blocked by validator", rejected: testJwtValid, session: testJwtValidWithAuthProvider,
			validator: token.ValidatorFunc(func(tkn string, _ token.Claims) bool { return tkn != testJwtValid })},
		{name: "provider not allowed", rejected: testJwtValidWrongProvider, session: testJwtValid},
	}
	sources := []struct {
		name string
		set  func(r *http.Request, tkn string)
	}{
		{name: "query", set: func(r *http.Request, tkn string) {
			q := r.URL.Query()
			q.Set("token", tkn)
			r.URL.RawQuery = q.Encode()
		}},
		{name: "header", set: func(r *http.Request, tkn string) { r.Header.Set("X-JWT", tkn) }},
	}

	for _, b := range branches {
		for _, src := range sources {
			for _, required := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s, %s, required=%v", b.name, src.name, required), func(t *testing.T) {
					a := makeTestAuth(t)
					if b.validator != nil {
						a.Validator = b.validator
					}
					// the wrapped handler writes nothing, so any Set-Cookie comes from the middleware
					mw := a.Auth
					if !required {
						mw = a.Trace
					}
					server := httptest.NewServer(mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
					defer server.Close()

					call := func(cookie string) *http.Response {
						req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
						require.NoError(t, err)
						req.AddCookie(&http.Cookie{Name: "JWT", Value: cookie})
						req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "random id"})
						src.set(req, b.rejected)
						resp, err := server.Client().Do(req)
						require.NoError(t, err)
						_ = resp.Body.Close()
						return resp
					}
					wantCode := http.StatusOK
					if required {
						wantCode = http.StatusUnauthorized
					}

					// a rejected token from the query or a header leaves the session cookie of the request alone
					resp := call(b.session)
					assert.Equal(t, wantCode, resp.StatusCode)
					assert.Empty(t, resp.Header.Values("Set-Cookie"), "the other session's cookies must stay")

					// the same rejected token is also the cookie: that session is cleared
					resp = call(b.rejected)
					assert.Equal(t, wantCode, resp.StatusCode)
					expired := map[string]bool{}
					for _, c := range resp.Cookies() {
						expired[c.Name] = c.MaxAge < 0
					}
					assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, expired)
				})
			}
		}
	}
}

func TestTraceRejectionKeepsHandlerContentType(t *testing.T) {
	tbl := []struct {
		name     string
		outerSet string // Content-Type set in front of Trace, empty for none
		want     string
	}{
		// the handler leaves the type to sniffing, as a file server or a template page may
		{name: "sniffed by the handler", want: "text/html; charset=utf-8"},
		// a handler in front of Trace sets the type, the wrapped handler only writes the body
		{name: "set before Trace", outerSet: "application/json", want: "application/json"},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			a := makeTestAuth(t)
			a.Validator = token.ValidatorFunc(func(string, token.Claims) bool { return false })
			page := a.Trace(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("<!DOCTYPE html><html><body>public page</body></html>"))
			}))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.outerSet != "" {
					w.Header().Set("Content-Type", tt.outerSet)
				}
				page.ServeHTTP(w, r)
			}))
			defer server.Close()

			req, err := http.NewRequest("GET", server.URL, http.NoBody)
			require.NoError(t, err)
			req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/"})
			req.Header.Add("X-XSRF-TOKEN", "random id")
			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tt.want, resp.Header.Get("Content-Type"))
			expired := map[string]bool{}
			for _, c := range resp.Cookies() {
				expired[c.Name] = c.MaxAge < 0
			}
			assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, expired)
		})
	}
}

func TestTraceRefreshFailureKeepsHandlerContentType(t *testing.T) {
	a := makeTestAuth(t)
	a.JWTService = token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		TokenDuration:  time.Second,
		CookieDuration: time.Hour * 24 * 31,
		AudienceReader: token.AudienceFunc(func() ([]string, error) { return []string{"test_sys"}, nil }),
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			claims.Audience = "other_sys"
			return claims
		}),
	})
	page := a.Trace(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>public page</body></html>"))
	}))
	server := httptest.NewServer(page)
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	expired := map[string]bool{}
	for _, c := range resp.Cookies() {
		expired[c.Name] = c.MaxAge < 0
	}
	assert.Equal(t, map[string]bool{"JWT": true, "XSRF-TOKEN": true}, expired)
}

func TestAuthJWTRefreshLogsUserID(t *testing.T) {
	var logged []string
	var mu sync.Mutex
	a := makeTestAuth(t)
	a.L = logger.Func(func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	})
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/"})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, logged, "[DEBUG] token refreshed for provider1_id1")
	for _, line := range logged {
		assert.NotContains(t, line, "me@example.com", "the user's attributes stay out of the log")
	}
}

func TestAuthJWtWithHandshake(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtWithHandshake)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "blocked user")
}

func TestAuthWithBasic(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "xyz")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "wrong token creds")

	a.AdminPasswd = "" // disable admin
	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "admin with basic not allowed")
}

func TestBasicAdminUserDoesNotLogPassword(t *testing.T) {
	const secret = "super-secret-attempted-passwd"
	var buf strings.Builder
	a := makeTestAuth(t)
	a.L = logger.Func(func(format string, args ...any) {
		fmt.Fprintf(&buf, format, args...)
	})

	r, err := http.NewRequest("GET", "/auth", http.NoBody)
	require.NoError(t, err)
	r.SetBasicAuth("admin", secret)

	assert.False(t, a.basicAdminUser(r), "wrong password must not authenticate")
	assert.NotContains(t, buf.String(), secret, "attempted password must not appear in logs")
	assert.Contains(t, buf.String(), "admin basic auth failed", "rejection should still be logged")
}

func TestAuthWithBasicChecker(t *testing.T) {
	a := makeTestAuth(t)
	a.AdminPasswd = "" // disable admin
	a.BasicAuthChecker = func(user, passwd string) (bool, token.User, error) {
		if user == "basic_user" && passwd == "123456" {
			return true, token.User{Name: user, Role: "test_r"}, nil
		}
		return false, token.User{}, fmt.Errorf("basic auth credentials check failed")
	}

	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("basic_user", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid basic user")

	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "xyz")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "wrong basic auth creds")

	a.BasicAuthChecker = nil // disable basicAuthChecker
	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "auth with basic not allowed")
}

func TestAuthNotRequired(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, false))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "no token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtWithHandshake)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "wrong token")
}

func TestAdminRequired(t *testing.T) {
	a := makeTestAuth(t)
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	}
	mux.Handle("/auth", a.AdminOnly(http.HandlerFunc(handler)))

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user, admin")

	adminUser.SetAdmin(false)
	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 403, resp.StatusCode, "valid token user, not admin")

	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "not authorized")

	req, err = http.NewRequest("GET", server.URL+"/auth", http.NoBody)
	require.NoError(t, err)
	req.Header.Add("X-JWT", "bad bad token")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "not authorized")
}

func TestRBAC(t *testing.T) {
	a := makeTestAuth(t)

	mux := http.NewServeMux()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		assert.NoError(t, err)
		assert.Equal(t, token.User{Name: "name1", ID: "provider1_id1", Picture: "http://example.com/pic.png",
			IP: "127.0.0.1", Email: "me@example.com", Audience: "test_sys",
			Attributes: map[string]any{"boola": true, "stra": "stra-val"},
			Role:       "employee"}, u)
		w.WriteHeader(201)
	})

	mux.Handle("/authForEmployees", a.RBAC("someone", "employee")(handler))
	mux.Handle("/authForExternals", a.RBAC("external")(handler))
	server := httptest.NewServer(mux)
	defer server.Close()

	// employee route only, token with employee role
	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req, err := http.NewRequest("GET", server.URL+"/authForEmployees", http.NoBody)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtWithRole, HttpOnly: true, Path: "/",
		MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	// employee route only, token without an employee role
	expiration = int(365 * 24 * time.Hour.Seconds()) //nolint
	req, err = http.NewRequest("GET", server.URL+"/authForEmployees", http.NoBody)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/",
		MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	client = &http.Client{Timeout: 5 * time.Second}
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 403, resp.StatusCode, "valid token user, incorrect role")

	// external route only, token with employee role
	req, err = http.NewRequest("GET", server.URL+"/authForExternals", http.NoBody)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtWithRole, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Access denied\n", string(data))
}

func makeTestMux(_ *testing.T, a *Authenticator, required bool) http.Handler {
	mux := http.NewServeMux()
	authMiddleware := a.Auth
	if !required {
		authMiddleware = a.Trace
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	}
	mux.Handle("/auth", authMiddleware(http.HandlerFunc(handler)))
	return mux
}

func makeTestAuth(_ *testing.T) Authenticator {

	j := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "xyz 12345", nil }),
		SecureCookies:  false,
		TokenDuration:  time.Second,
		CookieDuration: time.Hour * 24 * 31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	return Authenticator{
		AdminPasswd: "123456",
		JWTService:  j,
		Validator:   token.ValidatorFunc(func(token string, claims token.Claims) bool { return true }),
		L:           logger.Std,
		Providers: []provider.Service{
			{Provider: provider.DirectHandler{ProviderName: "provider1"}},
			{Provider: provider.DirectHandler{ProviderName: "provider2"}},
		},
	}
}

type testRefreshCache struct {
	data map[any]any
	sync.RWMutex
	hits, misses int32
}

func newTestRefreshCache() *testRefreshCache {
	return &testRefreshCache{data: make(map[any]any)}
}

func (c *testRefreshCache) Get(key any) (value any, ok bool) {
	c.RLock()
	defer c.RUnlock()
	value, ok = c.data[key]
	if ok {
		atomic.AddInt32(&c.hits, 1)
	} else {
		atomic.AddInt32(&c.misses, 1)
	}
	return value, ok
}

func (c *testRefreshCache) Set(key, value any) {
	c.Lock()
	defer c.Unlock()
	c.data[key] = value
}
