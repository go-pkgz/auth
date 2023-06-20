package provider

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

type customLoader struct{} // implement custom private key loader interface

func TestAppleHandler_NewApple(t *testing.T) {

	testIDToken := `eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ0ZXN0LmF1dGguZXhhbXBsZS5jb20iLCJzdWIiOiIwMDExMjIuNzg5M2Y3NmViZWRjNDExOGE3OTE3ZGFiOWE4YTllYTkuMTEyMiIsImlzcyI6Imh0dHBzOi8vYXBwbGVpZC5hcHBsZS5jb20iLCJleHAiOiIxOTIwNjQ3MTgyIiwiaWF0IjoiMTYyMDYzNzE4MiIsImVtYWlsIjoidGVzdEBlbWFpbC5jb20ifQ.CQCPa7ov-IdZ5bEKfhhnxEXafMAM_t6mj5OAnaoyy0A` // #nosec
	p := Params{
		URL:     "http://localhost",
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "cs",
	}

	aCfg := AppleConfig{
		ClientID: "auth.example.com",
		TeamID:   "AA11BB22CC",
		KeyID:    "BS2A79VCTT",
	}
	cl := customLoader{}

	ah, err := NewApple(p, aCfg, cl)
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)
	assert.Equal(t, ah.name, "apple")
	assert.Equal(t, ah.conf.ClientID, aCfg.ClientID)
	assert.NotEmpty(t, ah.conf.privateKey)
	assert.NotEmpty(t, ah.conf.clientSecret)

	testTokenClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(testIDToken, testTokenClaims, ah.tokenKeyFunc)
	assert.Error(t, err) // no need check token is valid for test token

	// testing mapUser
	u := ah.mapUser(testTokenClaims)
	t.Logf("%+v", u)
	assert.Equal(t, u.ID, "apple_"+token.HashID(sha1.New(), "001122.7893f76ebedc4118a7917dab9a8a9ea9.1122"))

	_, err = NewApple(p, aCfg, nil)
	require.Error(t, err)

	// check empty params
	aCfg.ClientID = ""
	_, err = NewApple(p, aCfg, cl)
	assert.Error(t, err, "required params missed: ClientID")
	aCfg.TeamID = ""
	_, err = NewApple(p, aCfg, cl)
	assert.Error(t, err, "required params missed: ClientID, TeamID")
	aCfg.KeyID = ""
	_, err = NewApple(p, aCfg, cl)
	assert.Error(t, err, "required params missed: ClientID, TeamID, KeyID")
}

// TestAppleHandler_LoadPrivateKey need for testing pre-defined loader from local file
func TestAppleHandler_LoadPrivateKey(t *testing.T) {
	testValidKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----` // #nosec
	testInvalidKey := `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKNwapOQ6rQJHetP
HRlJBIh1OsOsUBiXb3rXXE3xpWAxAha0MH+UPRblOko+5T2JqIb+xKf9Vi3oTM3t
KvffaOPtzKXZauscjq6NGzA3LgeiMy6q19pvkUUOlGYK6+Xfl+B7Xw6+hBMkQuGE
nUS8nkpR5mK4ne7djIyfHFfMu4ptAgMBAAECgYA+s0PPtMq1osG9oi4xoxeAGikf
JB3eMUptP+2DYW7mRibc+ueYKhB9lhcUoKhlQUhL8bUUFVZYakP8xD21thmQqnC4
f63asad0ycteJMLb3r+z26LHuCyOdPg1pyLk3oQ32lVQHBCYathRMcVznxOG16VK
I8BFfstJTaJu0lK/wQJBANYFGusBiZsJQ3utrQMVPpKmloO2++4q1v6ZR4puDQHx
TjLjAIgrkYfwTJBLBRZxec0E7TmuVQ9uJ+wMu/+7zaUCQQDDf2xMnQqYknJoKGq+
oAnyC66UqWC5xAnQS32mlnJ632JXA0pf9pb1SXAYExB1p9Dfqd3VAwQDwBsDDgP6
HD8pAkEA0lscNQZC2TaGtKZk2hXkdcH1SKru/g3vWTkRHxfCAznJUaza1fx0wzdG
GcES1Bdez0tbW4llI5By/skZc2eE3QJAFl6fOskBbGHde3Oce0F+wdZ6XIJhEgCP
iukIcKZoZQzoiMJUoVRrA5gqnmaYDI5uRRl/y57zt6YksR3KcLUIuQJAd242M/WF
6YAZat3q/wEeETeQq1wrooew+8lHl05/Nt0cCpV48RGEhJ83pzBm3mnwHf8lTBJH
x6XroMXsmbnsEw==
-----END PRIVATE KEY-----`
	testPrivKeyFileName := "privKeyTest.tmp"
	testBadPrivKeyFileName := "privKeyBadTest.tmp"

	dir, err := os.MkdirTemp(os.TempDir(), testPrivKeyFileName)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.RemoveAll(dir))
	}()

	tmpFn := filepath.Join(dir, testPrivKeyFileName)
	err = os.WriteFile(tmpFn, []byte(testValidKey), 0o600)
	require.NoError(t, err)
	badTmpFn := filepath.Join(dir, testBadPrivKeyFileName)
	err = os.WriteFile(badTmpFn, []byte(testInvalidKey), 0o600)
	require.NoError(t, err)
	p := Params{
		URL:     "http://localhost",
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "cs",
	}

	aCfg := AppleConfig{
		ClientID: "auth.example.com",
		TeamID:   "AA11BB22CC",
		KeyID:    "BS2A79VCTT",
	}

	// test good scenario
	ah, err := NewApple(p, aCfg, LoadApplePrivateKeyFromFile(tmpFn))
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)
	assert.Equal(t, ah.name, "apple")
	assert.Equal(t, ah.conf.ClientID, aCfg.ClientID)
	assert.NotEmpty(t, ah.conf.privateKey)
	assert.NotEmpty(t, ah.conf.publicKey)
	assert.NotEmpty(t, ah.conf.clientSecret)

	// test bad scenario, should not panic
	ah, err = NewApple(p, aCfg, LoadApplePrivateKeyFromFile(badTmpFn))
	assert.Error(t, err)
	assert.IsType(t, &AppleHandler{}, ah)
	assert.Empty(t, ah.conf.clientSecret, "client secret was not loaded")
	assert.Empty(t, ah.conf.publicKey, "public key was not loaded")
	assert.Equal(t, ah.name, "apple")
	assert.Equal(t, ah.conf.ClientID, aCfg.ClientID)
	assert.NotEmpty(t, ah.conf.privateKey)
}

func TestAppleHandlerCreateClientSecret(t *testing.T) {
	ah := &AppleHandler{}
	tkn, err := ah.createClientSecret()
	assert.Error(t, err)
	assert.Empty(t, tkn)

	ah, err = prepareAppleHandlerTest("", []string{})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	tkn, err = ah.createClientSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, tkn)

	testClaims := jwt.MapClaims{}

	parsedToken, err := jwt.ParseWithClaims(tkn, testClaims, ah.tokenKeyFunc)
	require.NoError(t, err)
	require.NotNil(t, parsedToken)
	assert.True(t, parsedToken.Valid)

	assert.Equal(t, "auth.example.com", testClaims["sub"])
}

func TestAppleParseUserData(t *testing.T) {

	ah := AppleHandler{Params: Params{L: logger.NoOp}}

	userNameClaimTest := `{"name":{"firstName":"test","lastName":"user"}}`
	testUser := &token.User{ID: "", Email: "user@example.com"}
	shaID := "apple_" + token.HashID(sha1.New(), testUser.ID)

	testUser.ID = shaID
	testCheckUser := &token.User{ID: shaID, Name: "test user", Email: "user@example.com"}

	ah.parseUserData(testUser, userNameClaimTest)
	assert.Equal(t, testUser, testCheckUser)

	testCheckUser.Name = "noname_" + shaID[6:12]
	ah.parseUserData(testUser, "")
	assert.Equal(t, testUser, testCheckUser)
}

func TestPrepareLoginURL(t *testing.T) {
	ah, err := prepareAppleHandlerTest("", []string{})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	lURL, err := ah.prepareLoginURL("1112233", "apple-test/login")
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(lURL, ah.endpoint.AuthURL))

	checkURL, err := url.Parse(lURL)
	assert.NoError(t, err)
	q := checkURL.Query()
	assert.Equal(t, q.Get("state"), "1112233")
	assert.Equal(t, q.Get("response_type"), "code")
	assert.Equal(t, q.Get("response_mode"), "form_post")
	assert.Equal(t, q.Get("client_id"), ah.conf.ClientID)
}

func TestPrepareLoginURLWithCustomResponseMode(t *testing.T) {
	ah, err := prepareAppleHandlerTest("query", []string{})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)
	ah.conf.scopes = []string{""}
	lURL, err := ah.prepareLoginURL("1112233", "apple-test/login")
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(lURL, ah.endpoint.AuthURL))

	checkURL, err := url.Parse(lURL)
	assert.NoError(t, err)
	q := checkURL.Query()
	assert.Equal(t, q.Get("state"), "1112233")
	assert.Equal(t, q.Get("response_type"), "code")
	assert.Equal(t, q.Get("response_mode"), "query")
	assert.Equal(t, q.Get("client_id"), ah.conf.ClientID)
}

func TestThrowsWhenNotEmptyScopeAndWrongResponseMode(t *testing.T) {
	ah, err := prepareAppleHandlerTest("query", []string{"email"})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	lURL, err := ah.prepareLoginURL("1112233", "apple-test/login")
	assert.Equal(t, "", lURL)
	assert.Error(t, err)
}

func TestAppleHandlerMakeRedirURL(t *testing.T) {
	cases := []struct{ rootURL, route, out string }{
		{"localhost:8080/", "/my/auth/path/apple", "localhost:8080/my/auth/path/callback"},
		{"localhost:8080", "/auth/apple", "localhost:8080/auth/callback"},
		{"localhost:8080/", "/auth/apple", "localhost:8080/auth/callback"},
		{"localhost:8080", "/", "localhost:8080/callback"},
		{"localhost:8080/", "/", "localhost:8080/callback"},
		{"mysite.com", "", "mysite.com/callback"},
	}

	ah, err := prepareAppleHandlerTest("", []string{})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	for i := range cases {
		c := cases[i]
		ah.URL = c.rootURL
		assert.Equal(t, c.out, ah.makeRedirURL(c.route))
	}
}

func TestAppleHandler_LoginHandler(t *testing.T) {

	teardown := prepareAppleOauthTest(t, 8981, 8982, nil)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost:8981/login?site=remark")
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

	u := token.User{}
	err = json.Unmarshal(body, &u)
	assert.NoError(t, err)
	testHashID := token.HashID(sha1.New(), "userid1")
	testUserID := "apple_" + testHashID
	testUserName := "noname_" + testUserID[6:12]
	assert.Equal(t, token.User{ID: testUserID, Name: testUserName}, u)

	tk := resp.Cookies()[0].Value
	jwtSvc := token.NewService(token.Opts{SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false,
		TokenDuration: time.Hour, CookieDuration: days31})

	claims, err := jwtSvc.Parse(tk)
	require.NoError(t, err)
	t.Log(claims)
	assert.Equal(t, "go-pkgz/auth", claims.Issuer)
	assert.Equal(t, "remark", claims.Audience)

}

func TestAppleHandler_LogoutHandler(t *testing.T) {

	teardown := prepareAppleOauthTest(t, 8691, 8692, nil)
	defer teardown()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", "http://localhost:8691/logout", http.NoBody)
	require.Nil(t, err)
	resp, err := client.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 403, resp.StatusCode, "user not lagged in")

	req, err = http.NewRequest("GET", "http://localhost:8691/logout", http.NoBody)
	require.NoError(t, err)
	expiration := int(365 * 24 * time.Hour.Seconds()) //nolint
	req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid, HttpOnly: true, Path: "/", MaxAge: expiration, Secure: false})
	req.Header.Add("X-XSRF-TOKEN", "random id")
	resp, err = client.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	assert.Equal(t, 2, len(resp.Cookies()))
	assert.Equal(t, "JWT", resp.Cookies()[0].Name, "token cookie cleared")
	assert.Equal(t, "", resp.Cookies()[0].Value)
	assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name, "xsrf cookie cleared")
	assert.Equal(t, "", resp.Cookies()[1].Value)

}

func TestAppleHandler_Exchange(t *testing.T) {
	var testResponseToken string
	teardown := prepareAppleOauthTest(t, 8981, 8982, &testResponseToken)
	defer teardown()

	ah, err := prepareAppleHandlerTest("", []string{})
	require.Nil(t, err)

	ah.endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", 8981),
		TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", 8982),
	}

	testAppleResponse := appleVerificationResponse{}
	err = ah.exchange(context.Background(), "1122334455", "url/callback", &testAppleResponse)
	assert.NoError(t, err)
	assert.Equal(t, &appleVerificationResponse{
		AccessToken:  "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
		ExpiresIn:    3600,
		TokenType:    "bearer",
		RefreshToken: "IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
		IDToken:      testResponseToken,
	}, &testAppleResponse)

	testAppleResponse = appleVerificationResponse{} // clear response for next checking
	err = ah.exchange(context.Background(), "test-error", "url/callback", &testAppleResponse)
	assert.Error(t, err)
	assert.Equal(t, &appleVerificationResponse{
		Error: "test error occurred",
	}, &testAppleResponse)

	err = ah.exchange(context.Background(), "test-json-error", "url/callback", &testAppleResponse)
	assert.Error(t, err)
	assert.EqualError(t, err, "unmarshalling data from apple service response failed: invalid character 'i' looking for beginning of value")
}

func (cl customLoader) LoadPrivateKey() ([]byte, error) {

	// valid p8 key
	testValidKey := []byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`)

	return testValidKey, nil
}

func prepareTestPrivateKey(t *testing.T) (filePath string, cancelFunc context.CancelFunc) {
	testValidKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`
	testPrivKeyFileName := "privKeyTest.tmp"

	dir, err := os.MkdirTemp(os.TempDir(), testPrivKeyFileName)
	assert.NoError(t, err)
	assert.NotNil(t, dir)
	if err != nil {
		log.Fatal(err)
		return "", nil
	}

	filePath = filepath.Join(dir, testPrivKeyFileName)
	err = os.WriteFile(filePath, []byte(testValidKey), 0o600)
	require.NoError(t, err)
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Second*60)

	go func() {
		<-ctx.Done()
		require.NoError(t, os.RemoveAll(dir))
	}()
	return filePath, cancelCtx
}

func prepareAppleHandlerTest(responseMode string, scopes []string) (*AppleHandler, error) {
	p := Params{
		URL:     "http://localhost",
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "cs",
	}

	aCfg := AppleConfig{
		ClientID:     "auth.example.com",
		TeamID:       "AA11BB22CC",
		KeyID:        "BS2A79VCTT",
		ResponseMode: responseMode,
		scopes:       scopes,
	}

	cl := customLoader{}
	return NewApple(p, aCfg, cl)
}

func prepareAppleOauthTest(t *testing.T, loginPort, authPort int, testToken *string) func() {
	signKey, testJWK := createTestSignKeyPairs(t)
	provider, err := prepareAppleHandlerTest("", []string{})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, provider)

	filePath, cancelCtx := prepareTestPrivateKey(t)
	if cancelCtx == nil {
		t.Fatal(fmt.Errorf("failed to create test private key file"))
		return nil
	}

	provider.name = "mock"
	provider.endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("http://localhost:%d/login/oauth/authorize", authPort),
		TokenURL: fmt.Sprintf("http://localhost:%d/login/oauth/access_token", authPort),
	}
	provider.conf.jwkURL = fmt.Sprintf("http://localhost:%d/keys", authPort)

	provider.PrivateKeyLoader = LoadApplePrivateKeyFromFile(filePath)
	require.NoError(t, err)

	// create self-signed JWT
	testResponseToken, err := createTestResponseToken(signKey)
	require.NoError(t, err)
	require.NotEmpty(t, testResponseToken)
	if testToken != nil {
		*testToken = testResponseToken
	}

	jwtService := token.NewService(token.Opts{
		SecretReader: token.SecretFunc(mockKeyStore), SecureCookies: false, TokenDuration: time.Hour, CookieDuration: days31,
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims {
			if claims.User != nil {
				switch claims.User.ID {
				case "mock_myuser2":
					claims.User.SetBoolAttr("admin", true)
				case "mock_myuser1":
					claims.User.Picture = "http://example.com/custom.png"
				}
			}
			return claims
		}),
	})

	params := Params{URL: "url", Cid: "cid", Csecret: "csecret", JwtService: jwtService,
		Issuer: "go-pkgz/auth", L: logger.Std}
	provider.Params = params

	svc := Service{Provider: provider}

	ts := &http.Server{Addr: fmt.Sprintf(":%d", loginPort), Handler: http.HandlerFunc(svc.Handler)} //nolint:gosec

	count := 0
	useIds := []string{"myuser1", "myuser2"} // user for first ans second calls

	oauth := &http.Server{ //nolint:gosec
		Addr: fmt.Sprintf(":%d", authPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[MOCK OAUTH] request %s %s %+v", r.Method, r.URL, r.Header)
			switch {
			case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):
				state := r.URL.Query().Get("state")
				w.Header().Add("Location", fmt.Sprintf("http://localhost:%d/callback?state=%s", loginPort, state))
				w.WriteHeader(302)
			case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
				err := r.ParseForm()
				assert.NoError(t, err)

				res := fmt.Sprintf(`{
					"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
					"token_type":"bearer",
					"expires_in":3600,
					"refresh_token":"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
					"id_token":"%s"
					}`, testResponseToken)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")

				switch r.Form.Get("code") {
				case "test-error":

					res = `{
					"error":"test error occurred"
					}`
					w.WriteHeader(http.StatusBadRequest)
					_, e := w.Write([]byte(res))
					assert.NoError(t, e)
					return

				case "test-json-error":
					res = `invalid json data`
					w.WriteHeader(http.StatusBadRequest)
					_, e := w.Write([]byte(res))
					assert.NoError(t, e)
					return
				}

				w.WriteHeader(200)
				_, err = w.Write([]byte(res))
				assert.NoError(t, err)
			case strings.HasPrefix(r.URL.Path, "/user"):
				res := fmt.Sprintf(`{
					"id": "%s",
					"name":"blah",
					"picture":"http://exmple.com/pic1.png"
					}`, useIds[count])
				count++
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(200)
				_, err := w.Write([]byte(res))
				assert.NoError(t, err)
			case strings.HasPrefix(r.URL.Path, "/keys"):

				testKeys := fmt.Sprintf(`{
					"keys": [
					%s,
					{
					  "kty": "RSA",
					  "kid": "eXaunmL",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
					  "e": "AQAB"
					},
					{
					  "kty": "RSA",
					  "kid": "YuyXoY",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
					  "e": "AQAB"
					}
				  ]
				}`, testJWK)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err := w.Write([]byte(testKeys))
				assert.NoError(t, err)
			default:
				t.Fatalf("unexpected oauth request %s %s", r.Method, r.URL)
			}
		}),
	}

	go func() { _ = oauth.ListenAndServe() }()
	go func() { _ = ts.ListenAndServe() }()

	time.Sleep(time.Millisecond * 100) // let them start

	return func() {

		assert.NoError(t, ts.Close())
		assert.NoError(t, oauth.Close())
		cancelCtx() // delete test private key file
	}
}

func createTestResponseToken(privKey interface{}) (string, error) {
	claims := &jwt.MapClaims{
		"iss":   "http://go.localhost.test",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Second * 30).Unix(),
		"aud":   "go-pkgz/auth",
		"sub":   "userid1",
		"email": "test@example.go",
	}

	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tkn.Header["alg"] = "RS256"
	tkn.Header["kid"] = "112233"

	return tkn.SignedString(privKey)
}

func createTestSignKeyPairs(t *testing.T) (privKey *rsa.PrivateKey, jwk string) {
	privateStr := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----`
	publicStr := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----`

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateStr))
	require.NoError(t, err)

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicStr))
	require.NoError(t, err)

	// convert modulus
	n := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(publicKey.N.Bytes())

	// convert exponent
	eBuff := make([]byte, 4)
	binary.LittleEndian.PutUint32(eBuff, uint32(publicKey.E))
	e := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(eBuff)

	JWK := struct {
		Alg string `json:"alg"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		E   string `json:"e"`
		N   string `json:"n"`
	}{Alg: "RS256", Kty: "RSA", Use: "sig", Kid: "112233", N: n, E: e[:4]}

	var buffJwk []byte
	buffJwk, err = json.Marshal(JWK)
	require.NoError(t, err)
	jwk = string(buffJwk)

	return signKey, jwk
}
