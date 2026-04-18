package provider

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-pkgz/auth/v2/token"
)

func TestIsAllowedRedirect(t *testing.T) {
	allowedFn := func(hosts ...string) token.AllowedHosts {
		return token.AllowedHostsFunc(func() ([]string, error) { return hosts, nil })
	}
	errFn := token.AllowedHostsFunc(func() ([]string, error) { return nil, errors.New("boom") })

	tests := []struct {
		name       string
		from       string
		serviceURL string
		allowed    token.AllowedHosts
		want       bool
	}{
		{name: "empty from", from: "", serviceURL: "https://app.example.com", want: false},
		{name: "relative path rejected", from: "/foo/bar", serviceURL: "https://app.example.com", want: false},
		{name: "unparseable url rejected", from: "://not a url", serviceURL: "https://app.example.com", want: false},
		{name: "same host as service allowed", from: "https://app.example.com/back", serviceURL: "https://app.example.com", want: true},
		{name: "same host different scheme allowed", from: "http://app.example.com/back", serviceURL: "https://app.example.com", want: true},
		{name: "same host with port matches", from: "https://app.example.com:443/x", serviceURL: "https://app.example.com:443", want: true},
		{name: "explicit https default port matches no-port service", from: "https://app.example.com:443/x", serviceURL: "https://app.example.com", want: true},
		{name: "explicit http default port matches no-port service", from: "http://app.example.com:80/x", serviceURL: "http://app.example.com", want: true},
		{name: "different non-default port still allowed (hostname compare)", from: "https://app.example.com:8080/x", serviceURL: "https://app.example.com", want: true},
		{name: "subdomain not implicitly allowed", from: "https://evil.app.example.com/x", serviceURL: "https://app.example.com", want: false},
		{name: "different host rejected when no allowlist", from: "https://evil.com/phish", serviceURL: "https://app.example.com", want: false},
		{name: "host in allowlist accepted", from: "https://admin.example.com/back", serviceURL: "https://app.example.com",
			allowed: allowedFn("admin.example.com", "other.example.com"), want: true},
		{name: "host not in allowlist rejected", from: "https://evil.com/phish", serviceURL: "https://app.example.com",
			allowed: allowedFn("admin.example.com"), want: false},
		{name: "allowlist getter error treated as not allowed", from: "https://admin.example.com", serviceURL: "https://app.example.com",
			allowed: errFn, want: false},
		{name: "service URL same host always wins over allowlist absence", from: "https://app.example.com/x", serviceURL: "https://app.example.com",
			allowed: allowedFn(), want: true},
		{name: "malformed service URL falls back to allowlist", from: "https://admin.example.com", serviceURL: "://bad",
			allowed: allowedFn("admin.example.com"), want: true},
		{name: "malformed service URL no allowlist rejects", from: "https://admin.example.com", serviceURL: "://bad", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAllowedRedirect(tt.from, tt.serviceURL, tt.allowed))
		})
	}
}

func TestRedirectHostForLog(t *testing.T) {
	tests := []struct {
		name string
		from string
		want string
	}{
		{name: "https URL with path and query", from: "https://evil.example.com/phish?token=abc", want: "evil.example.com"},
		{name: "URL with port", from: "https://evil.example.com:8080/path", want: "evil.example.com"},
		{name: "empty string", from: "", want: "<unparseable>"},
		{name: "relative path has no host", from: "/local/path", want: "<unparseable>"},
		{name: "garbage", from: "://not a url", want: "<unparseable>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, redirectHostForLog(tt.from))
		})
	}
}
