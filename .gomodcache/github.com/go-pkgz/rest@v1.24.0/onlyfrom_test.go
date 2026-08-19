package rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnlyFromAllowedIP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(OnlyFrom("127.0.0.1")(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/blah")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))
}

func TestOnlyFromAllowedHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(OnlyFrom("1.1.1.1")(handler))
	defer ts.Close()

	reqWithHeader := func(header string) (*http.Request, error) {
		req, err := http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set(header, "1.1.1.1")
		return req, err
	}
	client := http.Client{}

	t.Run("X-Real-IP", func(t *testing.T) {
		req, err := reqWithHeader("X-Real-IP")
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("X-Forwarded-For", func(t *testing.T) {
		req, err := reqWithHeader("X-Forwarded-For")
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("X-Forwarded-For and X-Real-IP missing", func(t *testing.T) {
		req, err := reqWithHeader("blah")
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, 403, resp.StatusCode)
	})
}

func TestOnlyFromAllowedCIDR(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(OnlyFrom("1.1.1.0/24")(handler))
	defer ts.Close()

	client := http.Client{}
	req, err := http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Real-IP", "1.1.1.1")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	req.Header.Set("X-Real-IP", "1.1.2.0")
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)
}

func TestMatchSourceIPRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []string
		source  string
		matched bool
	}{
		{name: "complete ipv4", rules: []string{"1.2.3.4"}, source: "1.2.3.4", matched: true},
		{name: "complete ipv4 rejects textual prefix", rules: []string{"1.2.3.4"}, source: "1.2.3.45", matched: false},
		{name: "ipv4 prefix", rules: []string{"1.2.3."}, source: "1.2.3.45", matched: true},
		{name: "ipv4 cidr", rules: []string{"1.2.3.0/24"}, source: "1.2.3.45", matched: true},
		{name: "complete ipv6 normalized", rules: []string{"2001:db8:0:0::1"}, source: "2001:db8::1", matched: true},
		{
			name: "complete ipv6 rejects textual prefix", rules: []string{"2001:db8::1"},
			source: "2001:db8::10", matched: false,
		},
		{name: "ipv6 prefix", rules: []string{"2001:db8:"}, source: "2001:db8::10", matched: true},
		{name: "ipv6 prefix rejects mismatch", rules: []string{"2001:db9:"}, source: "2001:db8::10", matched: false},
		{name: "ipv6 cidr", rules: []string{"2001:db8::/32"}, source: "2001:db8::10", matched: true},
		{name: "ipv6 cidr rejects mismatch", rules: []string{"2001:db9::/32"}, source: "2001:db8::10", matched: false},
		{name: "later rule matches", rules: []string{"1.2.3.4", "5.6."}, source: "5.6.7.8", matched: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set("X-Real-IP", tt.source)

			matched, source, err := matchSourceIP(req, tt.rules)
			require.NoError(t, err)
			assert.Equal(t, tt.matched, matched)
			assert.Equal(t, tt.source, source)
		})
	}
}

func TestOnlyFromRejected(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(OnlyFrom("127.0.0.2")(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/blah")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)
}

func TestOnlyFromErrors(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		status     int
	}{
		{
			name:       "Invalid RemoteAddr",
			remoteAddr: "bad-addr",
			status:     http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = tt.remoteAddr
				OnlyFrom("1.1.1.1")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, err := w.Write([]byte("blah blah"))
					require.NoError(t, err)
				})).ServeHTTP(w, r)
			})

			ts := httptest.NewServer(handler)
			defer ts.Close()

			req, err := http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
			require.NoError(t, err)

			client := http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}

func TestOnlyFromContentType(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	t.Run("rejected ip returns json content-type", func(t *testing.T) {
		ts := httptest.NewServer(OnlyFrom("1.1.1.1")(handler))
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/blah")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	})

	t.Run("invalid remote addr returns json content-type", func(t *testing.T) {
		outerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = "bad-addr"
			OnlyFrom("1.1.1.1")(handler).ServeHTTP(w, r)
		})
		ts := httptest.NewServer(outerHandler)
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/blah")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	})
}

func TestOnlyFrom_EmptyList(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("allowed"))
		require.NoError(t, err)
	})

	// empty list should allow all traffic
	ts := httptest.NewServer(OnlyFrom()(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/blah")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "allowed", string(b))
}
