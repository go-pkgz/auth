package middleware

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-pkgz/auth/token"
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
	mux.Handle("/token", a.Auth(http.HandlerFunc(handler)))
	server := httptest.NewServer(mux)
	defer server.Close()

	expiration := int(time.Duration(365 * 24 * time.Hour).Seconds())
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "wrong id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "xsrf mismatch")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtExpired, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtNoUser, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "no user info in the token")
}

func TestAuthJWTHeader(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, a, true))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtExpired)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "token expired and refreshed")
}

func TestAuthJWtBlocked(t *testing.T) {
	a := makeTestAuth(t)
	a.Validator = ValidatorFunc(func(token string, claims token.Claims) bool { return false })
	server := httptest.NewServer(makeTestMux(t, a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "blocked user")
}

func TestAuthJWtWithHandshake(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, a, true))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.Nil(t, err)
	req.Header.Add("X-JWT", testJwtWithHandshake)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "blocked user")
}

func TestAuthWithBasic(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, a, true))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "xyz")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "wrong token creds")
}

func TestAuthNotRequired(t *testing.T) {
	a := makeTestAuth(t)
	server := httptest.NewServer(makeTestMux(t, a, false))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "no token user")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user")

	req, err = http.NewRequest("GET", server.URL+"/token", nil)
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
	mux.Handle("/token", a.Auth(a.AdminOnly(http.HandlerFunc(handler))))

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", server.URL+"/token", nil)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "123456")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user, admin")

	devUser.SetAdmin(false)
	req, err = http.NewRequest("GET", server.URL+"/token", nil)
	require.NoError(t, err)
	req.SetBasicAuth("dev", "123456")
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 403, resp.StatusCode, "valid token user, not admin")
}

func TestAuthWithSecret(t *testing.T) {

	jwtService := token.NewService(token.Opts{
		SecretReader: token.SecretFunc(func(aud string) (string, error) {
			if aud != "test" {
				return "", errors.New("err")
			}
			return "secretkey", nil
		})})

	a := Authenticator{DevPasswd: "123456", JWTService: jwtService}
	server := httptest.NewServer(makeTestMux(t, a, true))
	defer server.Close()

	resp, err := http.Get(server.URL + "/token?secret=secretkey&aud=test")
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "valid token user with secret, admin")

	resp, err = http.Get(server.URL + "/token?secret=secretkey&aud=bad")
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "invalid aud for secret")

	resp, err = http.Get(server.URL + "/token?secret=badsecret&aud=test")
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode, "invalid token with bad secret")
}

func makeTestMux(t *testing.T, a Authenticator, required bool) http.Handler {
	mux := http.NewServeMux()
	authMiddleware := a.Auth
	if !required {
		authMiddleware = a.Trace
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	}
	mux.Handle("/token", authMiddleware(http.HandlerFunc(handler)))
	return mux
}

func makeTestAuth(t *testing.T) Authenticator {
	j := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(aud string) (string, error) { return "xyz 12345", nil }),
		SecureCookies:  false,
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24 * 31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	return Authenticator{
		DevPasswd:  "123456",
		JWTService: j,
		Validator:  ValidatorFunc(func(token string, claims token.Claims) bool { return true }),
	}
}
