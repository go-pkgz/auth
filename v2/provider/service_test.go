package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/token"
)

func TestHandler(t *testing.T) {

	tbl := []struct {
		method string
		url    string
		code   int
		resp   string
	}{
		{"GET", "/login", 200, "login"},
		{"POST", "/login", 200, "login"},
		{"GET", "/callback", 200, "callback"},
		{"GET", "/logout", 200, "logout"},
		{"GET", "/blah", 404, ""},
		{"PUT", "/login", 405, ""},
	}
	svc := NewService(&mockHandler{})
	handler := http.HandlerFunc(svc.Handler)

	for n, tt := range tbl {
		tt := tt
		t.Run(fmt.Sprintf("check-%d", n), func(t *testing.T) {
			rr := httptest.NewRecorder()
			req, err := http.NewRequest(tt.method, tt.url, http.NoBody)
			require.NoError(t, err)
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tt.code, rr.Code)
			assert.Equal(t, tt.resp, rr.Body.String())
		})
	}

}

func TestRandToken(t *testing.T) {
	s1, err := randToken()
	assert.NoError(t, err)
	assert.NotEqual(t, "", s1)
	t.Log(s1)

	s2, err := randToken()
	assert.NoError(t, err)
	assert.NotEqual(t, "", s2)
	assert.NotEqual(t, s2, s1)
	t.Log(s2)
}

func TestSetAvatar(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	u, err := setAvatar(nil, token.User{Picture: "http://example.com/pic1.png"}, client)
	assert.NoError(t, err, "nil ava allowed")
	assert.Equal(t, token.User{Picture: "http://example.com/pic1.png"}, u)

	u, err = setAvatar(mockAva{true, "http://example.com/pic1px.png"}, token.User{Picture: "http://example.com/pic1.png"}, client)
	assert.NoError(t, err)
	assert.Equal(t, token.User{Picture: "http://example.com/pic1px.png"}, u)

	_, err = setAvatar(mockAva{false, ""}, token.User{Picture: "http://example.com/pic1.png"}, client)
	assert.Error(t, err, "some error")
}

type mockAva struct {
	ok  bool
	res string
}

func (m mockAva) Put(token.User, *http.Client) (avatarURL string, err error) {
	if !m.ok {
		return "", fmt.Errorf("some error")
	}
	return m.res, nil
}

type mockHandler struct{}

func (n *mockHandler) Name() string { return "mock-handler" }
func (n *mockHandler) LoginHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("login"))
}
func (n *mockHandler) AuthHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("callback"))
}
func (n *mockHandler) LogoutHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("logout"))
}
