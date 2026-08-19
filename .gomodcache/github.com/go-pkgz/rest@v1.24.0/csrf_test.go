package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSRF_SafeMethods(t *testing.T) {
	protection := NewCrossOriginProtection()

	tests := []struct {
		method string
	}{
		{http.MethodGet},
		{http.MethodHead},
		{http.MethodOptions},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/data", http.NoBody)
			req.Header.Set("Origin", "https://evil.com")
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			err := protection.Check(req)
			assert.NoError(t, err, "safe methods should always pass")
		})
	}
}

func TestCSRF_UnsafeMethodsBlocked(t *testing.T) {
	protection := NewCrossOriginProtection()

	tests := []struct {
		method string
	}{
		{http.MethodPost},
		{http.MethodPut},
		{http.MethodDelete},
		{http.MethodPatch},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/data", http.NoBody)
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			err := protection.Check(req)
			assert.Error(t, err, "cross-site unsafe methods should be blocked")
		})
	}
}

func TestCSRF_SecFetchSite(t *testing.T) {
	protection := NewCrossOriginProtection()

	tests := []struct {
		name         string
		secFetchSite string
		shouldAllow  bool
	}{
		{name: "same-origin allowed", secFetchSite: "same-origin", shouldAllow: true},
		{name: "none allowed", secFetchSite: "none", shouldAllow: true},
		{name: "cross-site blocked", secFetchSite: "cross-site", shouldAllow: false},
		{name: "same-site blocked", secFetchSite: "same-site", shouldAllow: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)
			req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)

			err := protection.Check(req)
			if tt.shouldAllow {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCSRF_NoHeaders(t *testing.T) {
	protection := NewCrossOriginProtection()

	// request without Sec-Fetch-Site or Origin headers
	// should be allowed (assumed same-origin or non-browser)
	req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)

	err := protection.Check(req)
	assert.NoError(t, err, "requests without CSRF headers should be allowed")
}

func TestCSRF_OriginMatchesHost(t *testing.T) {
	protection := NewCrossOriginProtection()

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/data", http.NoBody)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://example.com")

	err := protection.Check(req)
	assert.NoError(t, err, "origin matching host should be allowed")
}

func TestCSRF_OriginMismatchHost(t *testing.T) {
	protection := NewCrossOriginProtection()

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/data", http.NoBody)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://evil.com")

	err := protection.Check(req)
	assert.Error(t, err, "origin not matching host should be blocked")
}

func TestCSRF_TrustedOrigin(t *testing.T) {
	protection := NewCrossOriginProtection()
	err := protection.AddTrustedOrigin("https://trusted.com")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://trusted.com")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	err = protection.Check(req)
	assert.NoError(t, err, "trusted origin should be allowed")
}

func TestCSRF_TrustedOriginCaseInsensitive(t *testing.T) {
	protection := NewCrossOriginProtection()
	err := protection.AddTrustedOrigin("https://TRUSTED.COM")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)
	req.Header.Set("Origin", "https://trusted.com")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	err = protection.Check(req)
	assert.NoError(t, err, "origin matching should be case-insensitive")
}

func TestCSRF_AddTrustedOriginValidation(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantError bool
	}{
		{name: "valid https", origin: "https://example.com", wantError: false},
		{name: "valid http", origin: "http://example.com", wantError: false},
		{name: "valid with port", origin: "https://example.com:8443", wantError: false},
		{name: "missing scheme", origin: "example.com", wantError: true},
		{name: "has path", origin: "https://example.com/path", wantError: true},
		{name: "has query", origin: "https://example.com?foo=bar", wantError: true},
		{name: "has fragment", origin: "https://example.com#section", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewCrossOriginProtection()
			err := p.AddTrustedOrigin(tt.origin)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCSRF_BypassPattern(t *testing.T) {
	protection := NewCrossOriginProtection()
	protection.AddBypassPattern("/webhook")
	protection.AddBypassPattern("/oauth/")

	tests := []struct {
		name        string
		path        string
		shouldAllow bool
	}{
		{name: "exact match", path: "/webhook", shouldAllow: true},
		{name: "prefix match", path: "/oauth/callback", shouldAllow: true},
		{name: "no match", path: "/api/data", shouldAllow: false},
		{name: "partial no match", path: "/webhooks", shouldAllow: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, http.NoBody)
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			err := protection.Check(req)
			if tt.shouldAllow {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCSRF_Handler(t *testing.T) {
	protection := NewCrossOriginProtection()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allowed request", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()

		protection.Handler(handler).ServeHTTP(w, req)

		assert.True(t, handlerCalled, "handler should be called for allowed requests")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("blocked request", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()

		protection.Handler(handler).ServeHTTP(w, req)

		assert.False(t, handlerCalled, "handler should not be called for blocked requests")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestCSRF_CustomDenyHandler(t *testing.T) {
	protection := NewCrossOriginProtection()

	customDenyCalled := false
	protection.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		customDenyCalled = true
		w.WriteHeader(http.StatusTeapot)
	}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/data", http.NoBody)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()

	protection.Handler(handler).ServeHTTP(w, req)

	assert.True(t, customDenyCalled, "custom deny handler should be called")
	assert.Equal(t, http.StatusTeapot, w.Code)
}

func TestCSRF_Integration(t *testing.T) {
	protection := NewCrossOriginProtection()
	err := protection.AddTrustedOrigin("https://mobile.example.com")
	require.NoError(t, err)
	protection.AddBypassPattern("/api/webhook")

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	ts := httptest.NewServer(protection.Handler(handler))
	defer ts.Close()

	client := &http.Client{}

	t.Run("GET always allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/data", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("POST same-origin allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/data", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("POST cross-site blocked", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/data", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("POST trusted origin allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/data", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Origin", "https://mobile.example.com")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("POST bypass pattern allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/webhook", http.NoBody)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
