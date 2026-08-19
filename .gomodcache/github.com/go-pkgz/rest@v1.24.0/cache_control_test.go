package rest

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRest_cacheControl(t *testing.T) {

	tbl := []struct {
		url     string
		version string
		exp     time.Duration
		etag    string
		maxAge  int
	}{
		{"http://example.com/foo", "v1", time.Hour, "b433be1ea19edaee9dc92ca4b895b6bdf3c058cb", 3600},
		{"http://example.com/foo2", "v1", 10 * time.Hour, "6d8466aef3246c1057452561acddf7ad9d0d99e0", 36000},
		{"http://example.com/foo", "v2", time.Hour, "481700c52aab0dfbca99f3ffc2a4fbb27884c114", 3600},
		{"https://example.com/foo", "v2", time.Hour, "bebd4f1b87f474792c4e75e5affe31fbf67f5778", 3600},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, http.NoBody)
			w := httptest.NewRecorder()

			h := CacheControl(tt.exp, tt.version)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
			h.ServeHTTP(w, req)
			resp := w.Result()
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			t.Logf("%+v", resp.Header)
			assert.Equal(t, `"`+tt.etag+`"`, resp.Header.Get("Etag"))
			assert.Equal(t, `max-age=`+strconv.Itoa(int(tt.exp.Seconds()))+", no-cache", resp.Header.Get("Cache-Control"))
		})
	}

}

func TestCacheControlDynamic(t *testing.T) {
	tbl := []struct {
		url     string
		version string
		exp     time.Duration
		etag    string
		maxAge  int
	}{
		{"http://example.com/foo", "v1", time.Hour, "b433be1ea19edaee9dc92ca4b895b6bdf3c058cb", 3600},
		{"http://example.com/foo2", "v1", 10 * time.Hour, "6d8466aef3246c1057452561acddf7ad9d0d99e0", 36000},
		{"http://example.com/foo", "v2", time.Hour, "481700c52aab0dfbca99f3ffc2a4fbb27884c114", 3600},
		{"https://example.com/foo", "v2", time.Hour, "bebd4f1b87f474792c4e75e5affe31fbf67f5778", 3600},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, http.NoBody)
			req.Header.Set("key", tt.version)
			w := httptest.NewRecorder()

			fn := func(r *http.Request) string {
				return r.Header.Get("key")
			}
			h := CacheControlDynamic(tt.exp, fn)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
			h.ServeHTTP(w, req)
			resp := w.Result()
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			t.Logf("%+v", resp.Header)
			assert.Equal(t, `"`+tt.etag+`"`, resp.Header.Get("Etag"))
			assert.Equal(t, `max-age=`+strconv.Itoa(int(tt.exp.Seconds()))+", no-cache", resp.Header.Get("Cache-Control"))
		})
	}
}

func TestCacheControl_IfNoneMatch(t *testing.T) {
	t.Run("matching etag returns 304", func(t *testing.T) {
		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			_, _ = w.Write([]byte("response body"))
		})
		req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
		// pre-computed etag for http://example.com/foo with version v1
		req.Header.Set("If-None-Match", `"b433be1ea19edaee9dc92ca4b895b6bdf3c058cb"`)
		w := httptest.NewRecorder()

		h := CacheControl(time.Hour, "v1")(handler)
		h.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotModified, resp.StatusCode)
		assert.False(t, handlerCalled, "handler should not be called on 304")
	})

	t.Run("non-matching etag returns 200", func(t *testing.T) {
		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			_, _ = w.Write([]byte("response body"))
		})
		req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
		req.Header.Set("If-None-Match", `"wrong-etag"`)
		w := httptest.NewRecorder()

		h := CacheControl(time.Hour, "v1")(handler)
		h.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, handlerCalled, "handler should be called on cache miss")
	})

	t.Run("no if-none-match returns 200", func(t *testing.T) {
		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			_, _ = w.Write([]byte("response body"))
		})
		req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
		w := httptest.NewRecorder()

		h := CacheControl(time.Hour, "v1")(handler)
		h.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, handlerCalled, "handler should be called without If-None-Match")
	})
}

func TestCacheControlDynamic_IfNoneMatch(t *testing.T) {
	versionFn := func(r *http.Request) string {
		return r.Header.Get("key")
	}

	t.Run("matching etag returns 304", func(t *testing.T) {
		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			_, _ = w.Write([]byte("response body"))
		})
		req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
		req.Header.Set("key", "v1")
		req.Header.Set("If-None-Match", `"b433be1ea19edaee9dc92ca4b895b6bdf3c058cb"`)
		w := httptest.NewRecorder()

		h := CacheControlDynamic(time.Hour, versionFn)(handler)
		h.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotModified, resp.StatusCode)
		assert.False(t, handlerCalled, "handler should not be called on 304")
	})

	t.Run("non-matching etag returns 200", func(t *testing.T) {
		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			_, _ = w.Write([]byte("response body"))
		})
		req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
		req.Header.Set("key", "v1")
		req.Header.Set("If-None-Match", `"wrong-etag"`)
		w := httptest.NewRecorder()

		h := CacheControlDynamic(time.Hour, versionFn)(handler)
		h.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, handlerCalled, "handler should be called on cache miss")
	})
}

func TestEtagMatches(t *testing.T) {
	const etag = `"abc123"`

	tbl := []struct {
		name   string
		header string
		want   bool
	}{
		{"empty header", "", false},
		{"exact match", `"abc123"`, true},
		{"no match", `"other"`, false},
		{"list, first", `"abc123", "other"`, true},
		{"list, last", `"other", "abc123"`, true},
		{"list, absent", `"one", "two"`, false},
		{"weak validator on header tag", `W/"abc123"`, true},
		{"weak validator in list", `"one", W/"abc123"`, true},
		{"wildcard alone does not match", "*", false},
		{"substring is not a match", `"abc12"`, false},
		{"superstring is not a match", `"abc1234"`, false},
		{"unquoted is not a match", "abc123", false},
		{"spacing tolerated", `   "abc123"   `, true},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, etagMatches([]string{tt.header}, etag))
		})
	}
}

func TestCacheControl_ConditionalMethods(t *testing.T) {
	// the etag of http://example.com/foo with version v1
	const knownEtag = `"b433be1ea19edaee9dc92ca4b895b6bdf3c058cb"`

	tbl := []struct {
		method     string
		wantStatus int
		wantCalled bool
	}{
		{http.MethodGet, http.StatusNotModified, false},
		{http.MethodHead, http.StatusNotModified, false},
		{http.MethodPut, http.StatusOK, true},
		{http.MethodPost, http.StatusOK, true},
		{http.MethodDelete, http.StatusOK, true},
		{http.MethodPatch, http.StatusOK, true},
	}

	for _, tt := range tbl {
		t.Run(tt.method, func(t *testing.T) {
			var called bool
			handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

			req := httptest.NewRequest(tt.method, "http://example.com/foo", http.NoBody)
			req.Header.Set("If-None-Match", knownEtag)
			w := httptest.NewRecorder()

			CacheControl(time.Hour, "v1")(handler).ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code, "unsafe methods carry preconditions this middleware doesn't enforce")
			assert.Equal(t, tt.wantCalled, called)
		})
	}
}

func TestEtagMatchesRepeatedFields(t *testing.T) {
	const etag = `"abc123"`

	tbl := []struct {
		name    string
		headers []string
		want    bool
	}{
		{"no fields", nil, false},
		{"single field, match", []string{`"abc123"`}, true},
		{"match in the second field", []string{`"one"`, `"abc123"`}, true},
		{"match in the third field", []string{`"one"`, `"two"`, `"abc123"`}, true},
		{"absent from every field", []string{`"one"`, `"two"`}, false},
		{"weak validator in a later field", []string{`"one"`, `W/"abc123"`}, true},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, etagMatches(tt.headers, etag))
		})
	}
}

func TestCacheControl_RepeatedIfNoneMatchHeader(t *testing.T) {
	// the etag of http://example.com/foo with version v1
	const knownEtag = `"b433be1ea19edaee9dc92ca4b895b6bdf3c058cb"`

	var called bool
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
	// repeated fields are one list, a match in any of them counts
	req.Header.Add("If-None-Match", `"something-else"`)
	req.Header.Add("If-None-Match", knownEtag)
	w := httptest.NewRecorder()

	CacheControl(time.Hour, "v1")(handler).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.False(t, called)
}

func TestCacheControl_HigherPriorityPreconditions(t *testing.T) {
	const knownEtag = `"b433be1ea19edaee9dc92ca4b895b6bdf3c058cb"`

	tbl := []struct {
		name       string
		header     string
		value      string
		wantStatus int
		wantCalled bool
	}{
		{"no other precondition", "", "", http.StatusNotModified, false},
		{"if-match present", "If-Match", `"other"`, http.StatusOK, true},
		{"if-unmodified-since present", "If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT", http.StatusOK, true},
		{"if-match present but empty", "If-Match", "", http.StatusOK, true},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

			req := httptest.NewRequest("GET", "http://example.com/foo", http.NoBody)
			req.Header.Set("If-None-Match", knownEtag)
			if tt.header != "" {
				req.Header.Add(tt.header, tt.value) // Add keeps an empty value as a present field
			}
			w := httptest.NewRecorder()

			CacheControl(time.Hour, "v1")(handler).ServeHTTP(w, req)

			// a 304 here would hide the 412 the handler may need to send
			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.wantCalled, called)
		})
	}
}
