package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/v2/avatar"
	"github.com/go-pkgz/auth/v2/token"
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

func TestLocalBindAddr(t *testing.T) {
	tests := []struct {
		name string
		host string
		port string
		want string
	}{
		{name: "empty host defaults to 127.0.0.1 (the security-relevant default)", host: "", port: "8080", want: "127.0.0.1:8080"},
		{name: "explicit 127.0.0.1 honored", host: "127.0.0.1", port: "8080", want: "127.0.0.1:8080"},
		{name: "explicit non-loopback honored (opt-in to LAN exposure)", host: "192.168.1.10", port: "8080", want: "192.168.1.10:8080"},
		{name: "explicit 0.0.0.0 honored (caller is asking for it)", host: "0.0.0.0", port: "8080", want: "0.0.0.0:8080"},
		{name: "ipv6 hostname is bracketed by net.JoinHostPort", host: "::1", port: "8080", want: "[::1]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, localBindAddr(tt.host, tt.port))
		})
	}
}

func TestLocalBindAddr_DefaultIsNotAllInterfaces(t *testing.T) {
	addr := localBindAddr("", "12345")
	assert.NotEqual(t, ":12345", addr, "default bind must not be all-interfaces")
	assert.False(t, strings.HasPrefix(addr, ":"), "default bind must include a hostname, not the bare-port shorthand")
}

func TestLogSummaries(t *testing.T) {
	assert.Equal(t, "keys=[email id name picture]", userDataLogSummary(UserData{
		"id":      "123",
		"name":    "Jane User",
		"email":   "secret@example.com",
		"picture": "https://example.com/pic.png",
	}))

	summary := userLogSummary(token.User{
		ID:      "provider_user123",
		Name:    "Jane User",
		Picture: "https://example.com/pic.png?token=secret",
		Email:   "secret@example.com",
		Attributes: map[string]any{
			"tier":  "gold",
			"admin": true,
		},
		Role:     "admin",
		Audience: "site1",
	})

	assert.Contains(t, summary, `id="provider_user123"`)
	assert.Contains(t, summary, `name="Jane User"`)
	assert.Contains(t, summary, "picture=true")
	assert.Contains(t, summary, "email=true")
	assert.Contains(t, summary, "attrs=[admin tier]")
	assert.Contains(t, summary, "role=true")
	assert.Contains(t, summary, "audience=true")
	assert.NotContains(t, summary, "secret@example.com")
	assert.NotContains(t, summary, "gold")
	assert.NotContains(t, summary, "https://example.com")
}

func TestSetAvatar(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	u, err := setAvatar(nil, token.User{Picture: "http://example.com/pic1.png"}, client)
	assert.NoError(t, err, "nil ava allowed")
	assert.Equal(t, token.User{Picture: "http://example.com/pic1.png"}, u)

	var nilProxy *avatar.Proxy
	var nilAva AvatarSaver = nilProxy
	u, err = setAvatar(nilAva, token.User{Picture: "http://example.com/pic1.png"}, client)
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
