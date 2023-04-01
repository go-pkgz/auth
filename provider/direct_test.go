package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

func TestDirect_LoginHandler(t *testing.T) {
	testCases := map[string]struct {
		makeRequest func(t *testing.T) *http.Request
	}{
		"GET": {
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123&from=http://example.com", http.NoBody)
				require.NoError(t, err)
				return req
			},
		},
		"POST application/x-www-form-urlencoded": {
			makeRequest: func(t *testing.T) *http.Request {
				form := url.Values{
					"user":   {"myuser"},
					"passwd": {"pppp"},
					"aud":    {"xyz123"},
				}
				req, err := http.NewRequest("POST", "/login?from=http://example.com", strings.NewReader(form.Encode()))
				require.NoError(t, err)
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
		},
		"POST application/json": {
			makeRequest: func(t *testing.T) *http.Request {
				jsonBody := `{"user":"myuser", "passwd":"pppp", "aud":"xyz123"}`
				req, err := http.NewRequest("POST", "/login?from=http://example.com", strings.NewReader(jsonBody))
				require.NoError(t, err)
				req.Header.Add("Content-Type", "application/json")
				return req
			},
		},
		"POST application/json; charset=utf-8": {
			makeRequest: func(t *testing.T) *http.Request {
				jsonBody := `{"user":"myuser", "passwd":"pppp", "aud":"xyz123"}`
				req, err := http.NewRequest("POST", "/login?from=http://example.com", strings.NewReader(jsonBody))
				require.NoError(t, err)
				req.Header.Add("Content-Type", "application/json")
				return req
			},
		},
	}

	for name, test := range testCases {
		test := test
		t.Run(name, func(t *testing.T) {
			d := DirectHandler{
				ProviderName: "test",
				CredChecker:  &mockCredsChecker{ok: true},
				TokenService: token.NewService(token.Opts{
					SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
					TokenDuration:  time.Hour,
					CookieDuration: time.Hour * 24 * 31,
				}),
				Issuer: "iss-test",
				L:      logger.Std,
			}

			assert.Equal(t, "test", d.Name())
			handler := http.HandlerFunc(d.LoginHandler)

			rr := httptest.NewRecorder()
			req := test.makeRequest(t)
			handler.ServeHTTP(rr, req)
			assert.Equal(t, 200, rr.Code)
			assert.Equal(t, `{"name":"myuser","id":"test_ed6307123e30cc7682328522d1d090d9c7525b32","picture":""}`+"\n", rr.Body.String())

			request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
			c, err := request.Cookie("JWT")
			require.NoError(t, err)
			claims, err := d.TokenService.Parse(c.Value)
			require.NoError(t, err)
			t.Logf("%+v", claims)
			assert.Equal(t, "xyz123", claims.Audience)
			assert.Equal(t, "iss-test", claims.Issuer)
			assert.True(t, claims.ExpiresAt > time.Now().Unix())
			assert.Equal(t, "myuser", claims.User.Name)
		})
	}
}

func TestDirect_LoginHandlerCustomUserID(t *testing.T) {
	d := DirectHandler{
		ProviderName: "test",
		CredChecker:  &mockCredsChecker{ok: true},
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
		UserIDFunc: func(user string, r *http.Request) string {
			return user + "_custom_id"
		},
	}

	assert.Equal(t, "test", d.Name())
	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123&from=http://example.com", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"myuser","id":"test_18c4eec1ecbe23902609e999c4d3da997e7ac10f","picture":""}`+"\n", rr.Body.String())
}

func TestDirect_LoginHandlerFailed(t *testing.T) {
	testCases := map[string]struct {
		makeRequest func(t *testing.T) *http.Request
		credChecker CredChecker
		wantCode    int
		wantBody    string
	}{
		"no credential checker": {
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", http.NoBody)
				require.NoError(t, err)
				return req
			},
			credChecker: nil,
			wantCode:    http.StatusInternalServerError,
			wantBody:    `{"error":"no credential checker"}`,
		},
		"failed to check user credentials": {
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", http.NoBody)
				require.NoError(t, err)
				return req
			},
			credChecker: &mockCredsChecker{err: fmt.Errorf("some err"), ok: false},
			wantCode:    http.StatusInternalServerError,
			wantBody:    `{"error":"failed to check user credentials"}`,
		},
		"incorrect user or password": {
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest("GET", "/login?user=myuser&passwd=pppp&aud=xyz123", http.NoBody)
				require.NoError(t, err)
				return req
			},
			credChecker: &mockCredsChecker{err: nil, ok: false},
			wantCode:    http.StatusForbidden,
			wantBody:    `{"error":"incorrect user or password"}`,
		},
		"malformed json body": {
			makeRequest: func(t *testing.T) *http.Request {
				jsonBody := `{"user":"myuser"`
				req, err := http.NewRequest("POST", "/login?from=http://example.com", strings.NewReader(jsonBody))
				require.NoError(t, err)
				req.Header.Add("Content-Type", "application/json")
				return req
			},
			credChecker: &mockCredsChecker{err: nil, ok: true},
			wantCode:    http.StatusBadRequest,
			wantBody:    `{"error":"failed to parse credentials"}`,
		},
		"malformed application/x-www-form-urlencoded body": {
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest("POST", "/login?from=http://example.com", nil) //nolint
				require.NoError(t, err)
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			credChecker: &mockCredsChecker{err: nil, ok: true},
			wantCode:    http.StatusBadRequest,
			wantBody:    `{"error":"failed to parse credentials"}`,
		},
	}

	for name, test := range testCases {
		test := test
		t.Run(name, func(t *testing.T) {
			d := DirectHandler{
				ProviderName: "test",
				CredChecker:  test.credChecker,
				TokenService: token.NewService(token.Opts{
					SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
					TokenDuration:  time.Hour,
					CookieDuration: time.Hour * 24 * 31,
				}),
				Issuer: "iss-test",
				L:      logger.Std,
			}

			handler := http.HandlerFunc(d.LoginHandler)
			rr := httptest.NewRecorder()
			req := test.makeRequest(t)
			handler.ServeHTTP(rr, req)
			assert.Equal(t, test.wantCode, rr.Code)
			assert.Equal(t, test.wantBody+"\n", rr.Body.String())
		})
	}
}

func TestDirect_Logout(t *testing.T) {
	d := DirectHandler{
		ProviderName: "test",
		CredChecker:  &mockCredsChecker{ok: true},
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, 2, len(rr.Header()["Set-Cookie"]))

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)

	c, err = request.Cookie("XSRF-TOKEN")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)
}

func TestDirect_AuthHandler(t *testing.T) {
	d := DirectHandler{}
	handler := http.HandlerFunc(d.AuthHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/callback", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
}

func TestDirect_CredChecker(t *testing.T) {
	ch := CredCheckerFunc(func(user string, password string) (ok bool, err error) {
		if user == "dev" && password == "password" {
			return true, nil
		}
		return false, nil
	})

	ok, err := ch.Check("user", "blah")
	assert.NoError(t, err)
	assert.False(t, ok)

	ok, err = ch.Check("dev", "password")
	assert.NoError(t, err)
	assert.True(t, ok)
}

type mockCredsChecker struct {
	ok  bool
	err error
}

func (m *mockCredsChecker) Check(string, string) (ok bool, err error) { return m.ok, m.err }
