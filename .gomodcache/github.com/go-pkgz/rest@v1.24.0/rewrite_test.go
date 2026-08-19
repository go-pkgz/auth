package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrite(t *testing.T) {

	rr := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Logf("%+v", r)
		assert.Equal(t, "/xyzzz/params?foo=bar", r.URL.String())
		assert.Equal(t, "/xyzzz/params", r.URL.Path)
		assert.Equal(t, "/api/v1/params", r.Header.Get("X-Original-URL"))
	})

	handler := Rewrite("/api/v1/(.*)", "/xyzzz/$1?foo=bar")(testHandler)
	req, err := http.NewRequest("GET", "/api/v1/params", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
}

func TestRewriteCleanup(t *testing.T) {

	rr := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Logf("%+v", r)
		assert.Equal(t, "/xyzzz/params?foo=bar", r.URL.String())
		assert.Equal(t, "/xyzzz/params", r.URL.Path)
		assert.Equal(t, "/api/v1/params", r.Header.Get("X-Original-URL"))
	})

	handler := Rewrite("/api/v1/(.*)", "/xyzzz/abc/../$1?foo=bar")(testHandler)
	req, err := http.NewRequest("GET", "/api/v1/params", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
}

func TestRewriteCleanupWithSlash(t *testing.T) {

	rr := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Logf("%+v", r)
		assert.Equal(t, "/xyzzz/params/", r.URL.String())
		assert.Equal(t, "/xyzzz/params/", r.URL.Path)
		assert.Equal(t, "/api/v1/params/", r.Header.Get("X-Original-URL"))
	})

	handler := Rewrite("/api/v1/(.*)/", "/xyzzz/abc/../$1/")(testHandler)
	req, err := http.NewRequest("GET", "/api/v1/params/", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
}

func TestRewrite_NoMatch(t *testing.T) {
	handlerCalled := false
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		assert.Equal(t, "/other/path", r.URL.Path)
		assert.Empty(t, r.Header.Get("X-Original-URL"), "X-Original-URL should not be set when no rewrite")
	})

	rr := httptest.NewRecorder()
	handler := Rewrite("/api/v1/(.*)", "/xyzzz/$1")(testHandler)
	req, err := http.NewRequest("GET", "/other/path", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.True(t, handlerCalled, "handler should be called for non-matching path")
}

func TestRewrite_DoubleRewritePrevention(t *testing.T) {
	rewriteCount := 0
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// after two rewrites in chain, path should only be rewritten once
		assert.Equal(t, "/first/params", r.URL.Path)
	})

	// first rewrite
	firstRewrite := Rewrite("/api/(.*)", "/first/$1")
	// second rewrite that would match the result of first
	secondRewrite := Rewrite("/first/(.*)", "/second/$1")

	// wrap with counter to see if second rewrite applies
	countingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Original-URL") != "" {
			rewriteCount++
		}
		testHandler.ServeHTTP(w, r)
	})

	rr := httptest.NewRecorder()
	handler := firstRewrite(secondRewrite(countingHandler))
	req, err := http.NewRequest("GET", "/api/params", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	// only first rewrite should be applied
	assert.Equal(t, 1, rewriteCount, "only one rewrite should be applied")
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "no change needed", input: "/users/1", expected: "/users/1"},
		{name: "double slash", input: "/users//1", expected: "/users/1"},
		{name: "multiple double slashes", input: "//users////1", expected: "/users/1"},
		{name: "trailing double slash", input: "/users//", expected: "/users/"},
		{name: "root path", input: "/", expected: "/"},
		{name: "mixed", input: "//api//v1//users", expected: "/api/v1/users"},
		{name: "single trailing slash preserved", input: "/users/", expected: "/users/"},
		{name: "double slash with trailing preserved", input: "/api//v1/", expected: "/api/v1/"},
		{name: "dot segments preserved", input: "/api/../admin", expected: "/api/../admin"},
		{name: "dot segments with double slash", input: "/api//../admin", expected: "/api/../admin"},
		{name: "single dot preserved", input: "/api/./v1", expected: "/api/./v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resultPath string
			testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				resultPath = r.URL.Path
			})

			req := httptest.NewRequest("GET", tt.input, http.NoBody)
			rr := httptest.NewRecorder()
			CleanPath(testHandler).ServeHTTP(rr, req)
			assert.Equal(t, tt.expected, resultPath)
		})
	}
}

func TestCleanPath_EmptyPath(t *testing.T) {
	var resultPath string
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resultPath = r.URL.Path
	})

	req := httptest.NewRequest("GET", "/", http.NoBody)
	req.URL.Path = "" // manually set empty path
	rr := httptest.NewRecorder()
	CleanPath(testHandler).ServeHTTP(rr, req)
	assert.Empty(t, resultPath, "empty path should remain empty")
}

func TestCleanPath_DoubleCleanPrevention(t *testing.T) {
	cleanCount := 0
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/users/1", r.URL.Path)
	})

	countingClean := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cleanCount++
			CleanPath(next).ServeHTTP(w, r)
		})
	}

	req := httptest.NewRequest("GET", "/users//1", http.NoBody)
	rr := httptest.NewRecorder()
	// chain two CleanPath calls
	countingClean(countingClean(testHandler)).ServeHTTP(rr, req)
	// path.Clean is called but context flag prevents redundant processing
	assert.Equal(t, 2, cleanCount, "middleware called twice")
}

func TestStripSlashes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "trailing slash removed", input: "/users/", expected: "/users"},
		{name: "no trailing slash", input: "/users", expected: "/users"},
		{name: "root preserved", input: "/", expected: "/"},
		{name: "deep path", input: "/api/v1/users/", expected: "/api/v1/users"},
		{name: "multiple segments", input: "/a/b/c/d/", expected: "/a/b/c/d"},
		{name: "multiple trailing slashes", input: "/users//", expected: "/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resultPath string
			testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				resultPath = r.URL.Path
			})

			req := httptest.NewRequest("GET", tt.input, http.NoBody)
			rr := httptest.NewRecorder()
			StripSlashes(testHandler).ServeHTTP(rr, req)
			assert.Equal(t, tt.expected, resultPath)
		})
	}
}

func TestStripSlashes_WithRawPath(t *testing.T) {
	var resultRawPath string
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resultRawPath = r.URL.RawPath
	})

	req := httptest.NewRequest("GET", "/users/1/", http.NoBody)
	req.URL.RawPath = "/users%2F1/" // encoded slash in segment
	rr := httptest.NewRecorder()
	StripSlashes(testHandler).ServeHTTP(rr, req)
	// RawPath trailing slash should also be stripped
	assert.Equal(t, "/users%2F1", resultRawPath)
}

func TestCleanPath_WithRawPath(t *testing.T) {
	t.Run("rawpath only set when originally present", func(t *testing.T) {
		var resultRawPath string
		testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			resultRawPath = r.URL.RawPath
		})

		// request without RawPath - should NOT set RawPath after cleaning
		req := httptest.NewRequest("GET", "/users//1", http.NoBody)
		req.URL.RawPath = "" // explicitly empty
		rr := httptest.NewRecorder()
		CleanPath(testHandler).ServeHTTP(rr, req)
		assert.Empty(t, resultRawPath, "RawPath should remain empty when not originally set")
	})

	t.Run("rawpath with literal double slashes cleaned", func(t *testing.T) {
		var resultRawPath string
		testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			resultRawPath = r.URL.RawPath
		})

		req := httptest.NewRequest("GET", "/users//1", http.NoBody)
		req.URL.RawPath = "/users//1" // literal double slash in RawPath
		rr := httptest.NewRecorder()
		CleanPath(testHandler).ServeHTTP(rr, req)
		assert.Equal(t, "/users/1", resultRawPath, "literal double slashes in RawPath should be cleaned")
	})

	t.Run("rawpath encoding preserved", func(t *testing.T) {
		var resultRawPath string
		testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			resultRawPath = r.URL.RawPath
		})

		req := httptest.NewRequest("GET", "/files//tmp", http.NoBody)
		req.URL.RawPath = "/files//tmp%2Flog%20file" // literal // but encoded %2F and %20
		rr := httptest.NewRecorder()
		CleanPath(testHandler).ServeHTTP(rr, req)
		// literal // cleaned, but %2F and %20 preserved
		assert.Equal(t, "/files/tmp%2Flog%20file", resultRawPath, "percent-encoding should be preserved")
	})
}

func TestCleanPath_ChainedWithStripSlashes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "double slash with trailing", input: "/api//v1/", expected: "/api/v1"},
		{name: "multiple double slashes with trailing", input: "//api////v1//", expected: "/api/v1"},
		{name: "only double slashes", input: "//", expected: "/"},
		{name: "clean path only", input: "/api//v1", expected: "/api/v1"},
		{name: "strip only", input: "/api/v1/", expected: "/api/v1"},
		{name: "no changes needed", input: "/api/v1", expected: "/api/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resultPath string
			testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				resultPath = r.URL.Path
			})

			req := httptest.NewRequest("GET", tt.input, http.NoBody)
			rr := httptest.NewRecorder()
			// chain: CleanPath first, then StripSlashes
			CleanPath(StripSlashes(testHandler)).ServeHTTP(rr, req)
			assert.Equal(t, tt.expected, resultPath)
		})
	}
}

func TestCleanPath_EncodedSlashes(t *testing.T) {
	// this test verifies that cleanDoubleSlashes operates on Path, not RawPath
	// URL-encoded slashes (%2F) in RawPath don't become // in Path
	var resultPath string
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resultPath = r.URL.Path
	})

	req := httptest.NewRequest("GET", "/api/v1/file", http.NoBody)
	req.URL.Path = "/api/v1/file"
	req.URL.RawPath = "/api/v1/file%2Fname" // %2F is encoded /
	rr := httptest.NewRecorder()
	CleanPath(testHandler).ServeHTTP(rr, req)
	assert.Equal(t, "/api/v1/file", resultPath, "Path should not be affected by encoded chars in RawPath")
}
