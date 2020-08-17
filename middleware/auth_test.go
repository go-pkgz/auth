package middleware

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

var testJwtValid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.OWPdibrSSSHuOV3DzzLH5soO6kUcERELL7_GLf7Ja_E"

var testJwtExpired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6MTE4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.lJNUjG_9rpAghqy5GwIOrgfQnGDnF3PW5sGzKdijmmg"

var testJwtWithHandshake = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0._2X1cAEoxjLA7XuN8xW8V9r7rYfP_m9lSRz_9_UFzac"

var testJwtNoUser = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI3ODkxOTE4MjIsImp0aSI6InJhbmRvbSBpZCIsImlzcyI6InJlbWFyazQyIiwibmJmIjoxNTI2ODg0MjIyfQ.sBpblkbBRzZsBSPPNrTWqA5h7h54solrw5L4IypJT_o"

var testJwtWithRole = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn0sInJvbGUiOiJlbXBsb3llZSJ9fQ.VLW4_LUDZq_eFc9F1Zx1lbv2Whic2VHy6C0dJ5azL8A"

func TestAuthJWTCookie(t *testing.T) {
	a := makeTestAuth(t)

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		assert.NoError(t, err)
		assert.Equal(t, token.User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png",
			IP: "127.0.0.1", Email: "me@example.com", Audience: "test_sys",
			Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, u)
		w.WriteHeader(201)
	}
	mux.Handle("/auth", a.Auth(http.HandlerFunc(handler)))
	server := httptest.NewServer(mux)
	defer server.Close()

	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "wrong id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "xsrf mismatch")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtNoUser, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "no user info in the token")
}

func TestAuthJWTHeader(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtExpired)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "token expired")
}

func TestAuthJWTRefresh(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
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
			req, err := http.NewRequest("GET", server.URL+"/auth", nil)
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
	c.User.ID = "other ID"
	tkSvc := a.JWTService.(*token.Service)
	tkn, err := tkSvc.Token(c)
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
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

type badJwtService struct {
	*token.Service
}

func (b *badJwtService) Set(w http.ResponseWriter, claims token.Claims) (token.Claims, error) {
	return token.Claims{}, errors.New("jwt set fake error")
}

func TestAuthJWTRefreshFailed(t *testing.T) {

	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	a.JWTService = &badJwtService{Service: a.JWTService.(*token.Service)}
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
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

	data, err := ioutil.ReadAll(resp.Body)
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
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
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
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
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
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "xyz")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "wrong token creds")

	a.AdminPasswd = "" // disable admin
	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "admin with basic not allowed")
}

func TestAuthNotRequired(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, false))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "no token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
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
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user, admin")

	adminUser.SetAdmin(false)
	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "123456")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 403, resp.StatusCode, "valid token user, not admin")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "not authorized")

	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
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
		assert.Equal(t, token.User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png",
			IP: "127.0.0.1", Email: "me@example.com", Audience: "test_sys",
			Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"},
			Role:       "employee"}, u)
		w.WriteHeader(201)
	})

	mux.Handle("/authForEmployees", a.RBAC("someone", "employee")(handler))
	mux.Handle("/authForExternals", a.RBAC("external")(handler))
	server := httptest.NewServer(mux)
	defer server.Close()

	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req, err := http.NewRequest("GET", server.URL+"/authForEmployees", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtWithRole, HttpOnly: true, Path: "/",
		MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/authForExternals", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtWithRole, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)

	data, err := ioutil.ReadAll(resp.Body)
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
