package token

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testJwtValid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0._2X1cAEoxjLA7XuN8xW8V9r7rYfP_m9lSRz_9_UFzac"

var testJwtValidSess = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJzZXNzX29ubHkiOnRydWUsImhhbmRzaGFrZSI6eyJzdGF0ZSI6IjEyMzQ1NiIsImZyb20iOiJmcm9tIiwiaWQiOiJteWlkLTEyMzQ1NiJ9fQ.1KuFNA-1DKI8QXszKPB7xl_H-0H6huKh-B232AXq9OA"

var testJwtExpired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MjY4ODc4MjIsImp0aSI6InJhbmRvbSBpZCIs" +
	"ImlzcyI6InJlbWFyazQyIiwibmJmIjoxNTI2ODg0MjIyLCJ1c2VyIjp7Im5hbWUiOiJuYW1lMSIsImlkIjoiaWQxIiwicGljdHVyZSI6IiI" +
	"sImFkbWluIjpmYWxzZX0sInN0YXRlIjoiMTIzNDU2IiwiZnJvbSI6ImZyb20ifQ.4_dCrY9ihyfZIedz-kZwBTxmxU1a52V7IqeJrOqTzE4"

var testJwtBadSign = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0.PRuys_Ez2QWhAMp3on4Xpdc5rebKcL7-HGncvYsdYns"

var days31 = time.Hour * 24 * 31

func mockKeyStore(aud string) (string, error) { return "xyz 12345", nil }

func TestJWT_NewDefault(t *testing.T) {
	j := NewService(Opts{})
	assert.Equal(t, "JWT", j.JWTCookieName)
	assert.Equal(t, "X-JWT", j.JWTHeaderKey)
	assert.Equal(t, "XSRF-TOKEN", j.XSRFCookieName)
	assert.Equal(t, "X-XSRF-TOKEN", j.XSRFHeaderKey)
	assert.Equal(t, "go-pkgz/auth", j.Issuer)
}

func TestJWT_NewNotDefault(t *testing.T) {
	j := NewService(Opts{JWTCookieName: "jc1", JWTHeaderKey: "jh1", XSRFCookieName: "xc1", XSRFHeaderKey: "xh1", Issuer: "i1"})
	assert.Equal(t, "jc1", j.JWTCookieName)
	assert.Equal(t, "jh1", j.JWTHeaderKey)
	assert.Equal(t, "xc1", j.XSRFCookieName)
	assert.Equal(t, "xh1", j.XSRFHeaderKey)
	assert.Equal(t, "i1", j.Issuer)
}

func TestJWT_Token(t *testing.T) {

	j := NewService(Opts{
		SecretReader:   SecretFunc(mockKeyStore),
		SecureCookies:  false,
		TokenDuration:  time.Hour,
		CookieDuration: days31,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims
	res, err := j.Token(claims)
	assert.Nil(t, err)
	assert.Equal(t, testJwtValid, res)
}

func TestJWT_Parse(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore)})
	claims, err := j.Parse(testJwtValid)
	assert.NoError(t, err)
	assert.False(t, j.IsExpired(claims))
	// assert.False(t, claims.Revoked)
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, claims.User)

	claims, err = j.Parse(testJwtExpired)
	assert.NoError(t, err)
	assert.True(t, j.IsExpired(claims))

	_, err = j.Parse("bad")
	assert.NotNil(t, err, "bad token")

	_, err = j.Parse(testJwtBadSign)
	assert.EqualError(t, err, "can't parse token: signature is invalid")

	j = NewService(Opts{
		SecretReader: SecretFunc(func(id string) (string, error) {
			return "bad 12345", nil
		}),
	})
	_, err = j.Parse(testJwtValid)
	assert.NotNil(t, err, "bad token", "valid token parsed with wrong secret")
}

func TestJWT_Set(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, Issuer: "remark42",
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims
	rr := httptest.NewRecorder()
	err := j.Set(rr, claims, claims.SessionOnly)
	assert.Nil(t, err)
	cookies := rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, "JWT", cookies[0].Name)
	assert.Equal(t, testJwtValid, cookies[0].Value)
	assert.Equal(t, 31*24*3600, cookies[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", cookies[1].Name)
	assert.Equal(t, "random id", cookies[1].Value)

	claims.SessionOnly = true
	rr = httptest.NewRecorder()
	err = j.Set(rr, claims, claims.SessionOnly)
	assert.Nil(t, err)
	cookies = rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, "JWT", cookies[0].Name)
	assert.Equal(t, testJwtValidSess, cookies[0].Value)
	assert.Equal(t, 0, cookies[0].MaxAge)
	assert.Equal(t, "XSRF-TOKEN", cookies[1].Name)
	assert.Equal(t, "random id", cookies[1].Value)
}

func TestJWT_GetFromHeader(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add(jwtHeaderKey, testJwtValid)
	claims, token, err := j.Get(req)
	assert.Nil(t, err)
	assert.Equal(t, testJwtValid, token)
	assert.False(t, j.IsExpired(claims))
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, claims.User)
	assert.Equal(t, "remark42", claims.Issuer)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Add(jwtHeaderKey, testJwtExpired)
	claims, token, err = j.Get(req)
	assert.Nil(t, err)
	assert.Equal(t, testJwtExpired, token)
	assert.True(t, j.IsExpired(claims))

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Add(jwtHeaderKey, "bad bad token")
	_, _, err = j.Get(req)
	require.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "can't pre-parse token: token contains an invalid number of segments"), err.Error())

}

func TestJWT_SetAndGetWithCookies(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims
	claims.SessionOnly = true

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid" {
			assert.Nil(t, j.Set(w, claims, true))
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/valid")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req := httptest.NewRequest("GET", "/valid", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfHeaderKey, "random id")
	r, _, err := j.Get(req)
	assert.Nil(t, err)
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, r.User)
	assert.Equal(t, "remark42", claims.Issuer)
	assert.Equal(t, true, claims.SessionOnly)
	t.Log(resp.Cookies())
}

func TestJWT_SetAndGetWithXsrfMismatch(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid" {
			assert.Nil(t, j.Set(w, claims, true))
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/valid")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req := httptest.NewRequest("GET", "/valid", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfHeaderKey, "random id wrong")
	_, _, err = j.Get(req)
	assert.EqualError(t, err, "xsrf mismatch")
}

func TestJWT_SetAndGetWithCookiesExpired(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims
	claims.StandardClaims.ExpiresAt = time.Date(2018, 5, 21, 1, 35, 22, 0, time.Local).Unix()
	claims.StandardClaims.NotBefore = time.Date(2018, 5, 21, 1, 30, 22, 0, time.Local).Unix()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/expired" {
			assert.Nil(t, j.Set(w, claims, true))
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/expired")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req := httptest.NewRequest("GET", "/expired", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfHeaderKey, "random id")
	r, _, err := j.Get(req)
	assert.Nil(t, err)
	assert.True(t, j.IsExpired(r))
}

var testClaims = Claims{
	StandardClaims: jwt.StandardClaims{
		Id:        "random id",
		Issuer:    "remark42",
		Audience:  "test_sys",
		ExpiresAt: time.Date(2058, 5, 21, 1, 30, 22, 0, time.Local).Unix(),
		NotBefore: time.Date(2018, 5, 21, 1, 30, 22, 0, time.Local).Unix(),
	},

	User: &User{
		ID:      "id1",
		Name:    "name1",
		IP:      "127.0.0.1",
		Email:   "me@example.com",
		Picture: "http://example.com/pic.png",
	},

	Handshake: &Handshake{
		From:  "from",
		State: "123456",
		ID:    "myid-123456",
	},
}
