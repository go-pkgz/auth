package provider

import (
	"net/url"

	"github.com/go-pkgz/auth/v2/token"
)

// isAllowedRedirect reports whether the "from" URL is safe to redirect to
// after a successful auth handshake. The service's own host (derived from
// serviceURL) is always allowed; any other host must appear in the allowed
// list. Relative paths and unparseable URLs are rejected to keep the rule
// unambiguous: callers must pass an absolute URL with a host.
func isAllowedRedirect(from, serviceURL string, allowed token.AllowedHosts) bool {
	u, err := url.Parse(from)
	if err != nil || u.Host == "" {
		return false
	}
	if svc, sErr := url.Parse(serviceURL); sErr == nil && svc.Host != "" && svc.Host == u.Host {
		return true
	}
	if allowed == nil {
		return false
	}
	hosts, hErr := allowed.Get()
	if hErr != nil {
		return false
	}
	for _, h := range hosts {
		if h == u.Host {
			return true
		}
	}
	return false
}
