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
		// permissive default (nil allowlist) — preserves pre-feature behavior
		{name: "nil allowlist allows arbitrary external host (legacy)", from: "https://evil.com/x", serviceURL: "https://app.example.com", want: true},
		{name: "nil allowlist allows relative path (legacy)", from: "/foo/bar", serviceURL: "https://app.example.com", want: true},
		{name: "nil allowlist rejects empty from", from: "", serviceURL: "https://app.example.com", want: false},
		{name: "typed-nil AllowedHostsFunc treated as nil allowlist", from: "https://evil.com/x", serviceURL: "https://app.example.com",
			allowed: token.AllowedHostsFunc(nil), want: true},

		// policy enabled (any non-nil allowlist) — sanity checks reject malformed input
		{name: "policy on: empty from rejected", from: "", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},
		{name: "policy on: relative path rejected", from: "/foo/bar", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},
		{name: "policy on: unparseable url rejected", from: "://not a url", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},

		// policy on, service URL host implicit
		{name: "policy on: same host as service allowed", from: "https://app.example.com/back", serviceURL: "https://app.example.com", allowed: allowedFn(), want: true},
		{name: "policy on: same host different scheme allowed", from: "http://app.example.com/back", serviceURL: "https://app.example.com", allowed: allowedFn(), want: true},
		{name: "policy on: same host with port matches", from: "https://app.example.com:443/x", serviceURL: "https://app.example.com:443", allowed: allowedFn(), want: true},
		{name: "policy on: explicit https default port matches no-port service", from: "https://app.example.com:443/x", serviceURL: "https://app.example.com", allowed: allowedFn(), want: true},
		{name: "policy on: explicit http default port matches no-port service", from: "http://app.example.com:80/x", serviceURL: "http://app.example.com", allowed: allowedFn(), want: true},
		{name: "policy on: different non-default port still allowed (hostname compare)", from: "https://app.example.com:8080/x", serviceURL: "https://app.example.com", allowed: allowedFn(), want: true},
		{name: "policy on: subdomain not implicitly allowed", from: "https://evil.app.example.com/x", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},
		{name: "policy on: different host rejected", from: "https://evil.com/phish", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},
		{name: "policy on: same host case-insensitive", from: "https://App.Example.Com/back", serviceURL: "https://app.example.com", allowed: allowedFn(), want: true},

		// non-http(s) schemes are rejected even if host looks sane
		{name: "policy on: javascript scheme rejected", from: "javascript:alert(1)", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},
		{name: "policy on: ftp scheme rejected", from: "ftp://app.example.com/file", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},
		{name: "policy on: data scheme rejected", from: "data:text/html,<script>alert(1)</script>", serviceURL: "https://app.example.com", allowed: allowedFn(), want: false},

		// policy with explicit allowlist entries
		{name: "host in allowlist accepted", from: "https://admin.example.com/back", serviceURL: "https://app.example.com",
			allowed: allowedFn("admin.example.com", "other.example.com"), want: true},
		{name: "host in allowlist case-insensitive", from: "https://Admin.Example.Com/back", serviceURL: "https://app.example.com",
			allowed: allowedFn("admin.example.com"), want: true},
		{name: "allowlist entry case-insensitive vs mixed-case from", from: "https://admin.example.com/back", serviceURL: "https://app.example.com",
			allowed: allowedFn("ADMIN.EXAMPLE.COM"), want: true},
		{name: "host not in allowlist rejected", from: "https://evil.com/phish", serviceURL: "https://app.example.com",
			allowed: allowedFn("admin.example.com"), want: false},
		{name: "allowlist getter error treated as not allowed", from: "https://admin.example.com", serviceURL: "https://app.example.com",
			allowed: errFn, want: false},
		{name: "malformed service URL falls back to allowlist", from: "https://admin.example.com", serviceURL: "://bad",
			allowed: allowedFn("admin.example.com"), want: true},
		{name: "malformed service URL with empty allowlist rejects", from: "https://admin.example.com", serviceURL: "://bad",
			allowed: allowedFn(), want: false},
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
