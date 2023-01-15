package token

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// To generate a token, enter one of the tokens here into https://jwt.io, change the secret to one you're using in your test
// ("secret" in most cases here, "xyz 12345" in makeTestAuth), and alter the fields you want to be changed.

var (
	testJwtValid            = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0._2X1cAEoxjLA7XuN8xW8V9r7rYfP_m9lSRz_9_UFzac"
	testJwtValidNoHandshake = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19fQ.OWPdibrSSSHuOV3DzzLH5soO6kUcERELL7_GLf7Ja_E"
	testJwtValidSess        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJzZXNzX29ubHkiOnRydWV9.SjPlVgca_bijC2wbaite2_eNHk66VXgsxUKLy7eqlXM"
	testJwtExpired          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MjY4ODc4MjIsImp0aSI6InJhbmRvbSBpZCIs" +
		"ImlzcyI6InJlbWFyazQyIiwibmJmIjoxNTI2ODg0MjIyLCJ1c2VyIjp7Im5hbWUiOiJuYW1lMSIsImlkIjoiaWQxIiwicGljdHVyZSI6IiI" +
		"sImFkbWluIjpmYWxzZX0sInN0YXRlIjoiMTIzNDU2IiwiZnJvbSI6ImZyb20ifQ.4_dCrY9ihyfZIedz-kZwBTxmxU1a52V7IqeJrOqTzE4"
	testJwtBadSign    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE1MjY4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0.PRuys_Ez2QWhAMp3on4Xpdc5rebKcL7-HGncvYsdYns"
	testJwtNbf        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X3N5cyIsImV4cCI6Mjc4OTE5MTgyMiwianRpIjoicmFuZG9tIGlkIiwiaXNzIjoicmVtYXJrNDIiLCJuYmYiOjE2OTk4ODQyMjIsInVzZXIiOnsibmFtZSI6Im5hbWUxIiwiaWQiOiJpZDEiLCJwaWN0dXJlIjoiaHR0cDovL2V4YW1wbGUuY29tL3BpYy5wbmciLCJpcCI6IjEyNy4wLjAuMSIsImVtYWlsIjoibWVAZXhhbXBsZS5jb20iLCJhdHRycyI6eyJib29sYSI6dHJ1ZSwic3RyYSI6InN0cmEtdmFsIn19LCJoYW5kc2hha2UiOnsic3RhdGUiOiIxMjM0NTYiLCJmcm9tIjoiZnJvbSIsImlkIjoibXlpZC0xMjM0NTYifX0.gJu5OWWlSgRnpa1S9iLr-PIB7a4VIr-CFY_2FcDJh7k"
	testJwtNoneAlg    = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTU0Njc0MzcxMSwiZXhwIjoxNTQ2NzQ3MzExLCJpYXQiOjE1NDY3NDM3MTEsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9."
	testJwtNoAud      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI3ODkxOTE4MjIsImp0aSI6InJhbmRvbSBpZCIsImlzcyI6InJlbWFyazQyIiwibmJmIjoxNTI2ODg0MjIyLCJ1c2VyIjp7Im5hbWUiOiJuYW1lMSIsImlkIjoiaWQxIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9waWMucG5nIiwiaXAiOiIxMjcuMC4wLjEiLCJlbWFpbCI6Im1lQGV4YW1wbGUuY29tIiwiYXR0cnMiOnsiYm9vbGEiOnRydWUsInN0cmEiOiJzdHJhLXZhbCJ9fSwiaGFuZHNoYWtlIjp7InN0YXRlIjoiMTIzNDU2IiwiZnJvbSI6ImZyb20iLCJpZCI6Im15aWQtMTIzNDU2In19.pzRsCcZjH7MItUvnBmyGv74Qg3qx8vCGmsZP6lF_Z9A"
	testJwtValidAud   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZF9vbmx5IiwiZXhwIjoyNzg5MTkxODIyLCJqdGkiOiJyYW5kb20gaWQiLCJpc3MiOiJyZW1hcms0MiIsIm5iZiI6MTUyNjg4NDIyMiwidXNlciI6eyJuYW1lIjoibmFtZTEiLCJpZCI6ImlkMSIsInBpY3R1cmUiOiJodHRwOi8vZXhhbXBsZS5jb20vcGljLnBuZyIsImlwIjoiMTI3LjAuMC4xIiwiZW1haWwiOiJtZUBleGFtcGxlLmNvbSIsImF0dHJzIjp7ImJvb2xhIjp0cnVlLCJzdHJhIjoic3RyYS12YWwifX0sImhhbmRzaGFrZSI6eyJzdGF0ZSI6IjEyMzQ1NiIsImZyb20iOiJmcm9tIiwiaWQiOiJteWlkLTEyMzQ1NiJ9fQ.Ll3uS2jvj_yYZms43_w6zJOdkDR305M4AiFVLXnSd7Y"
	testJwtNonAudSign = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0X2F1ZF9vbmx5IiwiZXhwIjoyNzg5MTkxODIyLCJqdGkiOiJyYW5kb20gaWQiLCJpc3MiOiJyZW1hcms0MiIsIm5iZiI6MTUyNjg4NDIyMiwidXNlciI6eyJuYW1lIjoibmFtZTEiLCJpZCI6ImlkMSIsInBpY3R1cmUiOiJodHRwOi8vZXhhbXBsZS5jb20vcGljLnBuZyIsImlwIjoiMTI3LjAuMC4xIiwiZW1haWwiOiJtZUBleGFtcGxlLmNvbSIsImF0dHJzIjp7ImJvb2xhIjp0cnVlLCJzdHJhIjoic3RyYS12YWwifX0sImhhbmRzaGFrZSI6eyJzdGF0ZSI6IjEyMzQ1NiIsImZyb20iOiJmcm9tIiwiaWQiOiJteWlkLTEyMzQ1NiJ9fQ.kJc-U970h3j9riUhFLR9vN_YCUQwZ66tjk7zdC9OiUg"
)

var days31 = time.Hour * 24 * 31

const (
	jwtCustomCookieName  = "jc1"
	jwtCustomHeaderKey   = "jh1"
	xsrfCustomCookieName = "xc1"
	xsrfCustomHeaderKey  = "xh1"
)

func mockKeyStore(aud string) (string, error) {
	if aud == "test_aud_only" {
		return "audsecret", nil
	}
	return "xyz 12345", nil
}

func TestJWT_NewDefault(t *testing.T) {
	j := NewService(Opts{})
	assert.Equal(t, defaultJWTCookieName, j.JWTCookieName)
	assert.Equal(t, defaultJWTCookieDomain, j.JWTCookieDomain)
	assert.Equal(t, defaultJWTHeaderKey, j.JWTHeaderKey)
	assert.Equal(t, defaultXSRFCookieName, j.XSRFCookieName)
	assert.Equal(t, defaultXSRFHeaderKey, j.XSRFHeaderKey)
	assert.Equal(t, defaultIssuer, j.Issuer)
}

func TestJWT_NewNotDefault(t *testing.T) {
	j := NewService(Opts{JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey, JWTCookieDomain: "blah.com",
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey, Issuer: "i1",
	})
	assert.Equal(t, jwtCustomCookieName, j.JWTCookieName)
	assert.Equal(t, jwtCustomHeaderKey, j.JWTHeaderKey)
	assert.Equal(t, xsrfCustomCookieName, j.XSRFCookieName)
	assert.Equal(t, xsrfCustomHeaderKey, j.XSRFHeaderKey)
	assert.Equal(t, "i1", j.Issuer)
	assert.Equal(t, "blah.com", j.JWTCookieDomain)
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
	assert.NoError(t, err)
	assert.Equal(t, testJwtValid, res)

	j.SecretReader = nil
	_, err = j.Token(claims)
	assert.EqualError(t, err, "secret reader not defined")

	j.SecretReader = SecretFunc(func(string) (string, error) { return "", fmt.Errorf("err blah") })
	_, err = j.Token(claims)
	assert.EqualError(t, err, "can't get secret: err blah")

	j.SecretReader = SecretFunc(mockKeyStore)
	j.AudienceReader = AudienceFunc(func() ([]string, error) { return []string{"a1", "aa2"}, nil })
	_, err = j.Token(claims)
	assert.EqualError(t, err, `aud rejected: aud "test_sys" not allowed`)

	j.AudienceReader = AudienceFunc(func() ([]string, error) { return []string{"a1", "test_sys", "aa2"}, nil })
	_, err = j.Token(claims)
	assert.NoError(t, err, "aud test_sys allowed")

}

func TestJWT_Parse(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore)})
	claims, err := j.Parse(testJwtValid)
	assert.NoError(t, err)
	assert.False(t, j.IsExpired(claims))
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, claims.User)

	claims, err = j.Parse(testJwtExpired)
	assert.NoError(t, err)
	assert.True(t, j.IsExpired(claims))

	_, err = j.Parse(testJwtNbf)
	assert.EqualError(t, err, "token is not valid yet")

	_, err = j.Parse("bad")
	assert.Error(t, err, "bad token")

	_, err = j.Parse(testJwtBadSign)
	assert.EqualError(t, err, "can't parse token: signature is invalid")

	_, err = j.Parse(testJwtNoneAlg)
	assert.EqualError(t, err, "can't parse token: unexpected signing method: none")

	j = NewService(Opts{
		SecretReader: SecretFunc(func(string) (string, error) { return "bad 12345", nil }),
	})
	_, err = j.Parse(testJwtValid)
	assert.Error(t, err, "bad token", "valid token parsed with wrong secret")

	j = NewService(Opts{
		SecretReader: SecretFunc(func(string) (string, error) { return "", fmt.Errorf("err blah") }),
	})
	_, err = j.Parse(testJwtValid)
	assert.EqualError(t, err, "can't get secret: err blah")

}

func TestJWT_Set(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, Issuer: "remark42",
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
		DisableIAT: true,
	})

	claims := testClaims
	claims.Handshake = nil

	rr := httptest.NewRecorder()
	c, err := j.Set(rr, claims)
	assert.NoError(t, err)
	assert.Equal(t, claims, c)
	cookies := rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, jwtCustomCookieName, cookies[0].Name)
	assert.Equal(t, testJwtValidNoHandshake, cookies[0].Value)
	assert.Equal(t, 31*24*3600, cookies[0].MaxAge)
	assert.Equal(t, xsrfCustomCookieName, cookies[1].Name)
	assert.Equal(t, "random id", cookies[1].Value)

	claims.SessionOnly = true
	rr = httptest.NewRecorder()
	_, err = j.Set(rr, claims)
	assert.NoError(t, err)
	cookies = rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, jwtCustomCookieName, cookies[0].Name)
	assert.Equal(t, testJwtValidSess, cookies[0].Value)
	assert.Equal(t, 0, cookies[0].MaxAge)
	assert.Equal(t, xsrfCustomCookieName, cookies[1].Name)
	assert.Equal(t, "random id", cookies[1].Value)
	assert.Equal(t, "", cookies[0].Domain)

	j.DisableIAT = false
	rr = httptest.NewRecorder()
	_, err = j.Set(rr, claims)
	assert.NoError(t, err)
	cookies = rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, jwtCustomCookieName, cookies[0].Name)
	assert.NotEqual(t, testJwtValidSess, cookies[0].Value, "iat changed the token")
	assert.Equal(t, "", rr.Result().Header.Get(jwtCustomHeaderKey), "no JWT header set")
}

func TestJWT_SetWithDomain(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, Issuer: "remark42",
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey, JWTCookieDomain: "example.com",
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
		DisableIAT: true,
	})

	claims := testClaims
	claims.Handshake = nil

	rr := httptest.NewRecorder()
	c, err := j.Set(rr, claims)
	assert.NoError(t, err)
	assert.Equal(t, claims, c)
	cookies := rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 2, len(cookies))
	assert.Equal(t, jwtCustomCookieName, cookies[0].Name)
	assert.Equal(t, "example.com", cookies[0].Domain)
	assert.Equal(t, testJwtValidNoHandshake, cookies[0].Value)
	assert.Equal(t, 31*24*3600, cookies[0].MaxAge)
	assert.Equal(t, xsrfCustomCookieName, cookies[1].Name)
	assert.Equal(t, "random id", cookies[1].Value)

}

func TestJWT_SendJWTHeader(t *testing.T) {

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
		DisableIAT:    true,
		SendJWTHeader: true,
	})

	rr := httptest.NewRecorder()
	_, err := j.Set(rr, testClaims)
	assert.NoError(t, err)
	cookies := rr.Result().Cookies()
	t.Log(cookies)
	require.Equal(t, 0, len(cookies), "no cookies set")
	assert.Equal(t, testJwtValid, rr.Result().Header.Get("X-JWT"))
}

func TestJWT_SetProlonged(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, Issuer: "remark42",
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims
	claims.Handshake = nil
	claims.ExpiresAt = 0

	rr := httptest.NewRecorder()
	_, err := j.Set(rr, claims)
	assert.NoError(t, err)
	cookies := rr.Result().Cookies()
	t.Log(cookies)
	assert.Equal(t, jwtCustomCookieName, cookies[0].Name)

	cc, err := j.Parse(cookies[0].Value)
	assert.NoError(t, err)
	assert.True(t, cc.ExpiresAt > time.Now().Unix())
}

func TestJWT_NoIssuer(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, Issuer: "xyz",
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	claims := testClaims
	claims.Handshake = nil
	claims.Issuer = ""

	rr := httptest.NewRecorder()
	_, err := j.Set(rr, claims)
	assert.NoError(t, err)
	cookies := rr.Result().Cookies()
	t.Log(cookies)
	assert.Equal(t, jwtCustomCookieName, cookies[0].Name)

	cc, err := j.Parse(cookies[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, "xyz", cc.Issuer)
}

func TestJWT_GetFromHeader(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add(jwtCustomHeaderKey, testJwtValid)
	claims, token, err := j.Get(req)
	assert.NoError(t, err)
	assert.Equal(t, testJwtValid, token)
	assert.False(t, j.IsExpired(claims))
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Audience: "test_sys",
		Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, claims.User)
	assert.Equal(t, "remark42", claims.Issuer)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Add(jwtCustomHeaderKey, testJwtExpired)
	_, _, err = j.Get(req)
	assert.Error(t, err)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Add(jwtCustomHeaderKey, "bad bad token")
	_, _, err = j.Get(req)
	require.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "failed to get token: can't parse token: token contains an invalid number of segments"), err.Error())
}

func TestJWT_GetFromQuery(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
	})

	req := httptest.NewRequest("GET", "/blah?token="+testJwtValid, nil)
	claims, token, err := j.Get(req)
	assert.NoError(t, err)
	assert.Equal(t, testJwtValid, token)
	assert.False(t, j.IsExpired(claims))
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Audience: "test_sys",
		Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, claims.User)
	assert.Equal(t, "remark42", claims.Issuer)

	req = httptest.NewRequest("GET", "/blah?token="+testJwtExpired, nil)
	_, _, err = j.Get(req)
	assert.Error(t, err)

	req = httptest.NewRequest("GET", "/blah?token=blah", nil)
	_, _, err = j.Get(req)
	require.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "failed to get token: can't parse token: token contains an invalid number of segments"), err.Error())
}

func TestJWT_GetFailed(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false})
	req := httptest.NewRequest("GET", "/", nil)
	_, _, err := j.Get(req)
	assert.Error(t, err, "token cookie was not presented")
}

func TestJWT_SetAndGetWithCookies(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
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
			_, e := j.Set(w, claims)
			require.NoError(t, e)
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/valid")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req := httptest.NewRequest("GET", "/valid", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfCustomHeaderKey, "random id")
	r, _, err := j.Get(req)
	assert.NoError(t, err)
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Audience: "test_sys",
		Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, r.User)
	assert.Equal(t, "remark42", claims.Issuer)
	assert.Equal(t, true, claims.SessionOnly)
	t.Log(resp.Cookies())
}

func TestJWT_SetAndGetWithXsrfMismatch(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
		Issuer:     "remark42",
		DisableIAT: true,
	})

	claims := testClaims
	claims.SessionOnly = true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid" {
			_, e := j.Set(w, claims)
			require.NoError(t, e)
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/valid")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req := httptest.NewRequest("GET", "/valid", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfCustomHeaderKey, "random id wrong")
	_, _, err = j.Get(req)
	assert.EqualError(t, err, "xsrf mismatch")

	j.DisableXSRF = true
	req = httptest.NewRequest("GET", "/valid", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfCustomHeaderKey, "random id wrong")
	c, _, err := j.Get(req)
	require.NoError(t, err, "xsrf mismatch, but ignored")
	claims.User.Audience = c.Audience // set aud to user because we don't do the normal Get call
	assert.Equal(t, claims, c)
}

func TestJWT_SetAndGetWithCookiesExpired(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		ClaimsUpd: ClaimsUpdFunc(func(claims Claims) Claims {
			claims.User.SetStrAttr("stra", "stra-val")
			claims.User.SetBoolAttr("boola", true)
			return claims
		}),
		DisableIAT: true,
	})

	claims := testClaims
	claims.StandardClaims.ExpiresAt = time.Date(2018, 5, 21, 1, 35, 22, 0, time.Local).Unix()
	claims.StandardClaims.NotBefore = time.Date(2018, 5, 21, 1, 30, 22, 0, time.Local).Unix()
	claims.SessionOnly = true

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/expired" {
			_, e := j.Set(w, claims)
			require.NoError(t, e)
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/expired")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	req := httptest.NewRequest("GET", "/expired", nil)
	req.AddCookie(resp.Cookies()[0])
	req.Header.Add(xsrfCustomHeaderKey, "random id")
	r, _, err := j.Get(req)
	assert.NoError(t, err)
	assert.True(t, j.IsExpired(r))
}

func TestJWT_Reset(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		JWTCookieName: jwtCustomCookieName, JWTHeaderKey: jwtCustomHeaderKey,
		XSRFCookieName: xsrfCustomCookieName, XSRFHeaderKey: xsrfCustomHeaderKey,
		TokenDuration: time.Hour, CookieDuration: days31,
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid" {
			j.Reset(w)
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/valid")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, "jc1=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0", resp.Header.Get("Set-Cookie"))
	assert.Equal(t, "0", resp.Header.Get("Content-Length"))
}

func TestJWT_Validator(t *testing.T) {
	ch := ValidatorFunc(func(token string, claims Claims) bool {
		return token == "good"
	})
	assert.True(t, ch.Validate("good", Claims{}))
	assert.False(t, ch.Validate("bad", Claims{}))
}

func TestClaims_String(t *testing.T) {
	s := testClaims.String()
	assert.True(t, strings.Contains(s, `"aud":"test_sys"`))
	assert.True(t, strings.Contains(s, `"exp":2789191822`))
	assert.True(t, strings.Contains(s, `"jti":"random id"`))
	assert.True(t, strings.Contains(s, `"iss":"remark42"`))
	assert.True(t, strings.Contains(s, `"nbf":1526884222`))
	assert.True(t, strings.Contains(s, `"user":`))
	assert.True(t, strings.Contains(s, `"name":"name1"`))
	assert.True(t, strings.Contains(s, `"picture":"http://example.com/pic.png"`))
}

func TestAudience(t *testing.T) {

	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31,
	})

	c := Claims{
		StandardClaims: jwt.StandardClaims{
			Audience: "au1",
			Issuer:   "test iss",
		},
	}

	assert.NoError(t, j.checkAuds(&c, nil), "any aud allowed")

	err := j.checkAuds(&c, AudienceFunc(func() ([]string, error) { return []string{"xxx", "yyy"}, nil }))
	assert.EqualError(t, err, `aud "au1" not allowed`)

	err = j.checkAuds(&c, AudienceFunc(func() ([]string, error) { return []string{"xxx", "yyy", "au1"}, nil }))
	assert.NoError(t, err, `au1 allowed`)
}

func TestAudReader(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, AudSecrets: true,
	})

	a, err := j.aud(testJwtValid)
	require.NoError(t, err)
	assert.Equal(t, "test_sys", a)

	a, err = j.aud(testJwtBadSign)
	require.NoError(t, err)
	assert.Equal(t, "test_sys", a)

	_, err = j.aud(testJwtNoAud)
	assert.EqualError(t, err, "empty aud")

	_, err = j.aud("blah bad bad")
	assert.EqualError(t, err, "can't pre-parse token: token contains an invalid number of segments")
}

func TestParseWithAud(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31, AudSecrets: true,
	})

	claims, err := j.Parse(testJwtValid)
	assert.NoError(t, err)
	assert.False(t, j.IsExpired(claims))
	assert.Equal(t, &User{Name: "name1", ID: "id1", Picture: "http://example.com/pic.png", IP: "127.0.0.1",
		Email: "me@example.com", Attributes: map[string]interface{}{"boola": true, "stra": "stra-val"}}, claims.User)

	claims, err = j.Parse(testJwtValidAud)
	assert.NoError(t, err)
	assert.Equal(t, "test_aud_only", claims.Audience)

	claims, err = j.Parse(testJwtNonAudSign)
	assert.EqualError(t, err, "can't parse token: signature is invalid")
}

var testClaims = Claims{
	StandardClaims: jwt.StandardClaims{
		Id:        "random id",
		Issuer:    "remark42",
		Audience:  "test_sys",
		ExpiresAt: time.Date(2058, 5, 21, 7, 30, 22, 0, time.UTC).Unix(),
		NotBefore: time.Date(2018, 5, 21, 6, 30, 22, 0, time.UTC).Unix(),
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
