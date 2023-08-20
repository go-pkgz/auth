package middleware

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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

func TestAuthJWTCookie(t *testing.T) {
	a := makeTestAuth(t)

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		assert.NoError(t, err)
		assert.Equal(t, token.User{Name: "name1", ID: "provider1_id1", Picture: "http://example.com/pic.png",
			IP: "127.0.0.1", Email: "me@example.com", Audience: "test_sys",
			Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, u)
		w.WriteHeader(201)
	}
	mux.Handle("/auth", a.Auth(http.HandlerFunc(handler)))
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	expiration := int(365 * 24 * time.Hour.Seconds()) // nolint

	t.Run("valid token", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
		req.Header.Add("X-XSRF-TOKEN", "random id")

		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 201, resp.StatusCode, "valid token user")
	})

	t.Run("valid token, wrong provider", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValidWrongProvider, HttpOnly: true, Path: "/",
			MaxAge: expiration, Secure: false})
		req.Header.Add("X-XSRF-TOKEN", "random id")

		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode, "user name1/provider3_id1 provider is not allowed")
	})

	t.Run("xsrf mismatch", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
		req.Header.Add("X-XSRF-TOKEN", "wrong id")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode, "xsrf mismatch")
	})

	t.Run("token expired and refreshed", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
		req.Header.Add("X-XSRF-TOKEN", "random id")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")
	})

	t.Run("no user info in the token", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.Nil(t, err)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtNoUser, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
		req.Header.Add("X-XSRF-TOKEN", "random id")
		resp, err := client.Do(req)
		require.NoError(t, err)
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

	expiration := int(365 * 24 * time.Hour.Seconds()) // nolint
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
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	var refreshCount int32
	var wg sync.WaitGroup
	a.RefreshCache = newTestRefreshCache()
	wg.Add(100)
	for i := 0; i < 100; i++ {
		time.Sleep(1 * time.Millisecond) // TODO! not sure how testRefreshCache may have misses without this delay
		go func() {
			defer wg.Done()
			jar, err := cookiejar.New(nil)
			require.Nil(t, err)
			client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
			req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
			require.NoError(t, err)

			expiration := int(365 * 24 * time.Hour.Seconds()) // nolint
			req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/",
				MaxAge: expiration, Secure: false})
			req.Header.Add("X-XSRF-TOKEN", "random id")

			resp, err := client.Do(req)
			require.NoError(t, err)
			assert.Equal(t, 201, resp.StatusCode)

			cookies := resp.Cookies()
			if len(cookies) == 2 && resp.Cookies()[0].Name == "JWT" && resp.Cookies()[0].Value != testJwtExpired {
				atomic.AddInt32(&refreshCount, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), a.RefreshCache.(*testRefreshCache).misses, "1 cache miss")
	assert.Equal(t, int32(99), a.RefreshCache.(*testRefreshCache).hits, "99 cache hits")
	assert.Equal(t, int32(1), atomic.LoadInt32(&refreshCount), "should make one refresh only")

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
	expiration := int(365 * 24 * time.Hour.Seconds()) // nolint
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

	expiration := int(365 * 24 * time.Hour.Seconds()) // nolint
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
			Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"},
			Role:       "employee"}, u)
		w.WriteHeader(201)
	})

	mux.Handle("/authForEmployees", a.RBAC("someone", "employee")(handler))
	mux.Handle("/authForExternals", a.RBAC("external")(handler))
	server := httptest.NewServer(mux)
	defer server.Close()

	// employee route only, token with employee role
	expiration := int(365 * 24 * time.Hour.Seconds()) // nolint
	req, err := http.NewRequest("GET", server.URL+"/authForEmployees", http.NoBody)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtWithRole, HttpOnly: true, Path: "/",
		MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	// employee route only, token without employee role
	expiration = int(365 * 24 * time.Hour.Seconds()) // nolint
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
	data map[interface{}]interface{}
	sync.RWMutex
	hits, misses int32
}

func newTestRefreshCache() *testRefreshCache {
	return &testRefreshCache{data: make(map[interface{}]interface{})}
}

func (c *testRefreshCache) Get(key interface{}) (value interface{}, ok bool) {
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

func (c *testRefreshCache) Set(key, value interface{}) {
	c.Lock()
	defer c.Unlock()
	c.data[key] = value
}
