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

func TestProfiler(t *testing.T) {
	ts := httptest.NewServer(Profiler())
	defer ts.Close()

	t.Run("pprof index", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "Types of profiles available")
	})

	t.Run("pprof cmdline", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/cmdline")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pprof symbol", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/symbol")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pprof heap", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/heap")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pprof goroutine", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/goroutine")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pprof block", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/block")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pprof threadcreate", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/pprof/threadcreate")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestProfiler_ExpVars(t *testing.T) {
	ts := httptest.NewServer(Profiler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/vars")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// expvar always has cmdline and memstats
	assert.True(t, strings.Contains(string(body), "cmdline"), "should contain cmdline")
	assert.True(t, strings.Contains(string(body), "memstats"), "should contain memstats")
	// should be valid JSON structure
	assert.True(t, strings.HasPrefix(string(body), "{"), "should start with {")
	assert.True(t, strings.HasSuffix(strings.TrimSpace(string(body)), "}"), "should end with }")
}

func TestProfiler_WithIPRestriction(t *testing.T) {
	ts := httptest.NewServer(Profiler("1.1.1.1"))
	defer ts.Close()

	// request from 127.0.0.1 should be blocked
	resp, err := http.Get(ts.URL + "/pprof/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, err = http.Get(ts.URL + "/vars")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestProfiler_AllowedIP(t *testing.T) {
	ts := httptest.NewServer(Profiler("127.0.0.1"))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/pprof/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Get(ts.URL + "/vars")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
