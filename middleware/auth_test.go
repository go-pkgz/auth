package middleware

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/lgr"
	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testJwtValid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.OWPdibrSSSHuOV3DzzLH5soO6kUcERELL7_GLf7Ja_E"

var testJwtExpired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6MTE4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.lJNUjG_9rpAghqy5GwIOrgfQnGDnF3PW5sGzKdijmmg"

var testJwtWithHandshake = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0._2X1cAEoxjLA7XuN8xW8V9r7rYfP_m9lSRz_9_UFzac"

var testJwtNoUser = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI3ODkxOTE4MjIsImp0aSI6InJhbmRvbSBpZCIsImlzcyI6InJlbWFyazQyIiwibmJmIjoxNTI2ODg0MjIyfQ.sBpblkbBRzZsBSPPNrTWqA5h7h54solrw5L4IypJT_o"

func TestAuthJWTCookie(t *testing.T) {
	a := makeTestAuth(t)

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		u, err := token.GetUserInfo(r)
		assert.NoError(t, err)
		assert.Equal(t, token.User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1", Email: "me@example.com", Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, u)
		w.WriteHeader(201)
	}
	mux.Handle("/auth", a.Auth(http.HandlerFunc(handler)))
	server := httptest.NewServer(mux)
	defer server.Close()

	expiration := int(time.Duration(365 * 24 * time.Hour).Seconds())
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
	assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")
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
	req.Header.Add("X-JWT", testJwtExpired)
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

type badJwtService struct {
	*token.Service
}

func (b *badJwtService) Set(w http.ResponseWriter, claims token.Claims) error {
	return errors.New("jwt set fake error")
}

func TestAuthJWTRefreshFailed(t *testing.T) {

	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, &a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtExpired)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")

	a.JWTService = &badJwtService{Service: a.JWTService.(*token.Service)}
	req, err = http.NewRequest("GET", server.URL+"/auth", nil)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtExpired)
	resp, err = client.Do(req)
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

func TestShouldRefresh(t *testing.T) {

	c := token.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience: "au1",
			Issuer:   "test iss",
		},
	}
	a := makeTestAuth(t)

	assert.True(t, a.shouldRefresh(c), "token with 0 time")

	c.ExpiresAt = time.Now().Unix() + 5
	assert.False(t, a.shouldRefresh(c), "token in the future 5s")

	c.ExpiresAt = time.Now().Unix() - 1
	for i := 0; i < 10; i++ {
		assert.True(t, a.shouldRefresh(c), "token in the past, factor 0")
	}

	a.RefreshFactor = 5
	refreshCount := 0
	for i := 0; i < 10; i++ {
		if a.shouldRefresh(c) {
			refreshCount++
		}
	}
	t.Logf("refreshes=%d", refreshCount)
	assert.True(t, refreshCount > 0 && refreshCount < 5, "refresh minimized")
}

func makeTestMux(t *testing.T, a *Authenticator, required bool) http.Handler {
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

func makeTestAuth(t *testing.T) Authenticator {
	j := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func() (string, error) { return "xyz 12345", nil }),
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
		L:           lgr.Std,
	}
}
