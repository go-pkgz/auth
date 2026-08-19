package rest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/rest/realip"
)

func TestMiddleware_AppInfo(t *testing.T) {
	err := os.Setenv("MHOST", "host1")
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err = w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(AppInfo("app-name", "Umputun", "12345")(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/blah")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, "blah blah", string(b))
	assert.Equal(t, "app-name", resp.Header.Get("App-Name"))
	assert.Equal(t, "12345", resp.Header.Get("App-Version"))
	assert.Equal(t, "Umputun", resp.Header.Get("Author"))
	assert.Equal(t, "host1", resp.Header.Get("Host"))
}

func TestMiddleware_Ping(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Ping(handler))
	defer ts.Close()

	t.Run("GET returns pong", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/ping")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "pong", string(b))
	})

	t.Run("HEAD returns 200 with no body", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, ts.URL+"/ping", http.NoBody)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Empty(t, b, "HEAD should return empty body")
	})

	t.Run("POST passes to next handler", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/ping", http.NoBody)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "blah blah", string(b))
	})

	t.Run("other paths pass to next handler", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/blah")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "blah blah", string(b))
	})
}

func TestMiddleware_Recoverer(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failed" {
			panic("oh my!")
		}
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})
	l := &mockLgr{}
	ts := httptest.NewServer(Recoverer(l)(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/failed")
	s := l.buf.String()
	t.Log("->> ", s)
	require.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)

	assert.Contains(t, s, "request panic for /failed from")
	assert.Contains(t, s, "oh my!")
	assert.Contains(t, s, "goroutine")
	assert.Contains(t, s, "github.com/go-pkgz/rest.TestMiddleware_Recoverer")

	resp, err = http.Get(ts.URL + "/blah")
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))
}

func TestMiddleware_RecovererAbortHandler(t *testing.T) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	})
	l := &mockLgr{}

	t.Run("propagated to the caller", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/failed", http.NoBody)
		w := httptest.NewRecorder()
		assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
			Recoverer(l)(handler).ServeHTTP(w, req)
		})
		assert.Empty(t, l.buf.String(), "abort sentinel should not be logged")
		assert.Empty(t, w.Body.String(), "no error body should be written")
	})

	t.Run("connection aborted without response", func(t *testing.T) {
		// net/http recovers the sentinel itself and closes the connection without a reply
		ts := httptest.NewServer(Recoverer(l)(handler))
		defer ts.Close()

		_, err := http.Get(ts.URL + "/failed")
		require.Error(t, err, "server must drop the connection instead of answering 500")
	})
}

func TestWrap(t *testing.T) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Logf("%s", r.URL.String())
	})

	mw1 := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-MW1", "1")
			h.ServeHTTP(w, r)
		})
	}
	mw2 := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-MW2", "2")
			h.ServeHTTP(w, r)
		})
	}

	t.Run("no middleware", func(t *testing.T) {
		h := Wrap(handler)
		ts := httptest.NewServer(h)
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/something")
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "", resp.Header.Get("X-MW1"))
		assert.Equal(t, "", resp.Header.Get("X-MW2"))
	})

	t.Run("with middleware", func(t *testing.T) {
		h := Wrap(handler, mw1, mw2)
		ts := httptest.NewServer(h)
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/something")
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("X-MW1"))
		assert.Equal(t, "2", resp.Header.Get("X-MW2"))
	})
}

func TestHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/something", http.NoBody)
	w := httptest.NewRecorder()

	h := Headers("h1:v1", "bad", "h2:v2")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	h.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	t.Logf("%+v", req.Header)
	assert.Equal(t, "v1", req.Header.Get("h1"))
	assert.Equal(t, "v2", req.Header.Get("h2"))
	assert.Equal(t, 2, len(req.Header))
}

func TestMaybe(t *testing.T) {
	var count int32
	h := Maybe(Headers("h1:v1", "bad", "h2:v2"), func(*http.Request) bool {
		return atomic.AddInt32(&count, 1) == 1
	})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

	{
		req := httptest.NewRequest("GET", "/something", http.NoBody)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("%+v", req.Header)
		assert.Equal(t, "v1", req.Header.Get("h1"))
		assert.Equal(t, "v2", req.Header.Get("h2"))
		assert.Equal(t, 2, len(req.Header))
	}
	{
		req := httptest.NewRequest("GET", "/something", http.NoBody)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("%+v", req.Header)
		assert.Equal(t, "", req.Header.Get("h1"))
		assert.Equal(t, "", req.Header.Get("h2"))
		assert.Equal(t, 0, len(req.Header))
	}
}

func TestRealIP(t *testing.T) {

	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Logf("%v", r)
		require.Equal(t, "1.2.3.4", r.RemoteAddr)
		adr, err := realip.Get(r)
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", adr)
	})

	ts := httptest.NewServer(RealIP(handler))

	req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
	require.NoError(t, err)
	client := http.Client{Timeout: time.Second}
	req.Header.Add("X-Real-IP", "1.2.3.4")
	_, err = client.Do(req)
	require.NoError(t, err)
}

func TestHealthPassed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	check1 := func(context.Context) (string, error) {
		return "check1", nil
	}
	check2 := func(context.Context) (string, error) {
		return "check2", nil
	}

	ts := httptest.NewServer(Health("/health", check1, check2)(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, `[{"name":"check1","status":"ok"},{"name":"check2","status":"ok"}]`+"\n", string(b))

	resp, err = http.Get(ts.URL + "/blah")
	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	b, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))
}

func TestHealthFailed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	check1 := func(context.Context) (string, error) {
		return "check1", nil
	}
	check2 := func(context.Context) (string, error) {
		return "check2", errors.New("some error")
	}

	ts := httptest.NewServer(Health("/health", check1, check2)(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	require.Nil(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, `[{"name":"check1","status":"ok"},{"name":"check2","status":"failed","error":"some error"}]`+"\n", string(b))
}

func TestHealthContentType(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	t.Run("healthy returns json content-type", func(t *testing.T) {
		check := func(context.Context) (string, error) {
			return "check1", nil
		}
		ts := httptest.NewServer(Health("/health", check)(handler))
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	})

	t.Run("unhealthy returns json content-type", func(t *testing.T) {
		check := func(context.Context) (string, error) {
			return "check1", errors.New("some error")
		}
		ts := httptest.NewServer(Health("/health", check)(handler))
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	})
}

func TestReject(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	rej := Reject(http.StatusForbidden, "no no", func(r *http.Request) bool {
		return r.Header.Get("h1") == "v1"
	})

	ts := httptest.NewServer(rej(handler))
	defer ts.Close()

	client := http.Client{Timeout: time.Second}
	{ // not rejected
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, `blah blah`, string(b))
	}
	{ // rejected
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		req.Header.Add("h1", "v1")
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "no no\n", string(b))
	}
}

type mockLgr struct {
	buf bytes.Buffer
}

func (m *mockLgr) Logf(format string, args ...any) {
	_, _ = m.buf.WriteString(fmt.Sprintf(format+"\n", args...))
}
