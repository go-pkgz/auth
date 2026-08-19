package rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Metrics("127.0.0.1")(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(string(b), "cmdline"))
	assert.True(t, strings.Contains(string(b), "memstats"))
}

func TestMetrics_EmptyList(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	// no ips means nobody is allowed, expvar must stay unreachable
	ts := httptest.NewServer(Metrics()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/metrics", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Real-IP", "1.2.3.4")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestMetricsAllowAll(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	ts := httptest.NewServer(MetricsAllowAll()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/metrics", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Real-IP", "1.2.3.4") // any source is served once opted in

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(b), "cmdline")
	assert.Contains(t, string(b), "memstats")
}

func TestMetricsAllowAll_NonMetricsPath(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("other path"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(MetricsAllowAll()(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/other")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "other path", string(b))
}

func TestMetricsRejected(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Metrics("1.1.1.1")(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)
}

func TestMetricsContentType(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Metrics("1.1.1.1")(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
}

func TestMetrics_NonGetRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("handler response"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Metrics("127.0.0.1")(handler))
	defer ts.Close()

	// POST to /metrics should pass to handler
	resp, err := http.Post(ts.URL+"/metrics", "text/plain", strings.NewReader("data"))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "handler response", string(b))
}

func TestMetrics_NonMetricsPath(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("other path"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Metrics("127.0.0.1")(handler))
	defer ts.Close()

	// GET to other path should pass to handler
	resp, err := http.Get(ts.URL + "/other")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "other path", string(b))
}
