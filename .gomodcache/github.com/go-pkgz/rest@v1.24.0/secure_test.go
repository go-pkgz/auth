package rest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecure_Defaults(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(Secure()(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
	// HSTS not set for HTTP
	assert.Empty(t, resp.Header.Get("Strict-Transport-Security"))
	// CSP and Permissions-Policy not set by default
	assert.Empty(t, resp.Header.Get("Content-Security-Policy"))
	assert.Empty(t, resp.Header.Get("Permissions-Policy"))
}

func TestSecure_HSTS_HTTPS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("HSTS via TLS connection", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.TLS = &tls.ConnectionState{} // simulate TLS connection
		w := httptest.NewRecorder()

		Secure()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
	})

	t.Run("HSTS via X-Forwarded-Proto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()

		Secure()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
	})

	t.Run("HSTS via Forwarded header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Forwarded", "proto=https")
		w := httptest.NewRecorder()

		Secure()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
	})

	t.Run("no HSTS for HTTP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		Secure()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Empty(t, resp.Header.Get("Strict-Transport-Security"))
	})
}

func TestSecure_CustomOptions(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("custom frame options", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		Secure(SecFrameOptions("SAMEORIGIN"))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "SAMEORIGIN", resp.Header.Get("X-Frame-Options"))
	})

	t.Run("disable content type nosniff", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		Secure(SecContentTypeNosniff(false))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Empty(t, resp.Header.Get("X-Content-Type-Options"))
	})

	t.Run("custom referrer policy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		Secure(SecReferrerPolicy("no-referrer"))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	})

	t.Run("custom CSP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		csp := "default-src 'self'; script-src 'self'"
		Secure(SecContentSecurityPolicy(csp))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, csp, resp.Header.Get("Content-Security-Policy"))
	})

	t.Run("custom permissions policy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		pp := "geolocation=(), camera=()"
		Secure(SecPermissionsPolicy(pp))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, pp, resp.Header.Get("Permissions-Policy"))
	})

	t.Run("custom HSTS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()

		Secure(SecHSTS(86400, false, true))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "max-age=86400; preload", resp.Header.Get("Strict-Transport-Security"))
	})

	t.Run("disable HSTS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()

		Secure(SecHSTS(0, false, false))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Empty(t, resp.Header.Get("Strict-Transport-Security"))
	})

	t.Run("disable XSS protection", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		w := httptest.NewRecorder()

		Secure(SecXSSProtection(""))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Empty(t, resp.Header.Get("X-XSS-Protection"))
	})
}

func TestSecure_AllHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	Secure(SecAllHeaders())(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	// default headers
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
	assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=31536000")

	// additional headers from SecAllHeaders
	csp := resp.Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")

	pp := resp.Header.Get("Permissions-Policy")
	assert.Contains(t, pp, "geolocation=()")
	assert.Contains(t, pp, "microphone=()")
	assert.Contains(t, pp, "camera=()")
}

func TestSecure_MultipleOptions(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	Secure(
		SecFrameOptions("SAMEORIGIN"),
		SecReferrerPolicy("same-origin"),
		SecHSTS(3600, true, false),
		SecContentSecurityPolicy("default-src 'none'"),
	)(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, "SAMEORIGIN", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "same-origin", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "max-age=3600; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
	assert.Equal(t, "default-src 'none'", resp.Header.Get("Content-Security-Policy"))
	// defaults still applied
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
}

func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected bool
	}{
		{name: "plain http", setup: func(r *http.Request) {}, expected: false},
		{name: "tls connection", setup: func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, expected: true},
		{name: "x-forwarded-proto https", setup: func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }, expected: true},
		{name: "x-forwarded-proto http", setup: func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }, expected: false},
		{name: "x-forwarded-proto HTTPS uppercase", setup: func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "HTTPS") }, expected: true},
		{name: "forwarded proto=https", setup: func(r *http.Request) { r.Header.Set("Forwarded", "proto=https") }, expected: true},
		{name: "forwarded with semicolon", setup: func(r *http.Request) { r.Header.Set("Forwarded", "for=1.2.3.4;proto=https") }, expected: true},
		{name: "forwarded with comma", setup: func(r *http.Request) { r.Header.Set("Forwarded", "for=1.2.3.4, proto=https") }, expected: true},
		{name: "forwarded proto=http", setup: func(r *http.Request) { r.Header.Set("Forwarded", "proto=http") }, expected: false},
		{name: "forwarded PROTO=HTTPS uppercase", setup: func(r *http.Request) { r.Header.Set("Forwarded", "PROTO=HTTPS") }, expected: true},
		{name: "forwarded complex", setup: func(r *http.Request) { r.Header.Set("Forwarded", "for=192.0.2.60;proto=https;by=203.0.113.43") }, expected: true},
		{name: "forwarded multiple elements", setup: func(r *http.Request) { r.Header.Set("Forwarded", "for=1.1.1.1;proto=http, for=2.2.2.2;proto=https") }, expected: true},
		{name: "forwarded with spaces", setup: func(r *http.Request) { r.Header.Set("Forwarded", "for=1.2.3.4; proto=https") }, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", http.NoBody)
			tt.setup(req)
			assert.Equal(t, tt.expected, isHTTPS(req))
		})
	}
}

func TestForwardedProtoIsHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{name: "simple proto=https", header: "proto=https", expected: true},
		{name: "simple proto=http", header: "proto=http", expected: false},
		{name: "uppercase PROTO=HTTPS", header: "PROTO=HTTPS", expected: true},
		{name: "mixed case Proto=Https", header: "Proto=Https", expected: true},
		{name: "with for directive", header: "for=192.0.2.60;proto=https", expected: true},
		{name: "full rfc example", header: "for=192.0.2.60;proto=https;by=203.0.113.43", expected: true},
		{name: "multiple proxies first http", header: "for=1.1.1.1;proto=http, for=2.2.2.2;proto=https", expected: true},
		{name: "multiple proxies all http", header: "for=1.1.1.1;proto=http, for=2.2.2.2;proto=http", expected: false},
		{name: "with spaces", header: "for=1.2.3.4; proto=https ; by=proxy", expected: true},
		{name: "proto at start", header: "proto=https;for=1.2.3.4", expected: true},
		{name: "proto at end", header: "for=1.2.3.4;by=proxy;proto=https", expected: true},
		{name: "empty string", header: "", expected: false},
		{name: "no proto", header: "for=1.2.3.4;by=proxy", expected: false},
		{name: "proto value with trailing space", header: "proto=https ", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, forwardedProtoIsHTTPS(tt.header))
		})
	}
}
