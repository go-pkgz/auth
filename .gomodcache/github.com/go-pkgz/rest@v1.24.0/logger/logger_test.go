package logger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggerMinimal(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), Log(lb))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/blah", "", bytes.NewBufferString("1234567890 abcdefg"))
	require.Nil(t, err)
	defer resp.Body.Close() // nolint
	assert.Equal(t, 200, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))

	s := lb.buf.String()
	t.Log(s)
	prefix := "[INFO] REST POST - /blah - 127.0.0.1 - 127.0.0.1 - 200 (9) - "
	assert.True(t, strings.HasPrefix(s, prefix), s)
	_, err = time.ParseDuration(s[len(prefix):])
	assert.NoError(t, err)

}

func TestLoggerMinimalLocalhost(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), Log(lb))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	port := strings.Split(ts.URL, ":")[2]
	resp, err := http.Post("http://localhost:"+port+"/blah", "", bytes.NewBufferString("1234567890 abcdefg"))
	require.Nil(t, err)
	defer resp.Body.Close() // nolint
	assert.Equal(t, 200, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))

	s := lb.buf.String()
	t.Log(s)
	prefix := "[INFO] REST POST - /blah - localhost - 127.0.0.1 - 200 (9) - "
	assert.True(t, strings.HasPrefix(s, prefix), s)
	_, err = time.ParseDuration(s[len(prefix):])
	assert.NoError(t, err)
}

func TestLogger(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), WithBody,
		Log(lb),
		IPfn(func(ip string) string {
			return ip + "!masked"
		}),
		UserFn(func(*http.Request) (string, error) {
			return "user", nil
		}),
		SubjFn(func(*http.Request) (string, error) {
			return "subj", nil
		}),
	)

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/blah?password=secret&key=val&var=123", "", bytes.NewBufferString("1234567890 abcdefg"))
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close() // nolint
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))

	s := lb.buf.String()
	t.Log(s)
	assert.True(t, strings.Contains(s, "[INFO] REST POST - /blah?key=val&password=********&var=123 - 127.0.0.1 - 127.0.0.1!masked - 200 (9) -"), s)
	assert.True(t, strings.HasSuffix(s, "- user - subj - 1234567890 abcdefg"))
}

func TestLoggerIP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Log(lb), Prefix("[INFO] REST"), IPfn(func(ip string) string { return ip + "!masked" }))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	clint := http.Client{}

	req, err := http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
	require.NoError(t, err)
	resp, err := clint.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	s := lb.buf.String()
	t.Log(s)
	assert.True(t, strings.Contains(s, "- 127.0.0.1!masked -"))

	lb.buf.Reset()
	req, err = http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err = clint.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	s = lb.buf.String()
	t.Log(s)
	assert.True(t, strings.Contains(s, "- 1.2.3.4!masked -"))
}

func TestLoggerIPAnon(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Log(lb), Prefix("[INFO] REST"), IPfn(AnonymizeIP))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	clint := http.Client{}

	req, err := http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
	require.NoError(t, err)
	resp, err := clint.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	s := lb.buf.String()
	t.Log(s)
	assert.True(t, strings.Contains(s, "- 127.0.0.0 -"), s)

	lb.buf.Reset()
	req, err = http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err = clint.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	s = lb.buf.String()
	t.Log(s)
	assert.True(t, strings.Contains(s, "- 1.2.3.0 -"), s)
}

func TestLoggerTraceID(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), WithBody,
		Log(lb),
		IPfn(func(ip string) string {
			return ip + "!masked"
		}),
		UserFn(func(*http.Request) (string, error) {
			return "user", nil
		}),
		SubjFn(func(*http.Request) (string, error) {
			return "subj", nil
		}),
	)

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	clint := http.Client{}
	req, err := http.NewRequest("GET", ts.URL+"/blah", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Request-ID", "0000-reqid")
	resp, err := clint.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	s := lb.buf.String()
	t.Log(s)
	assert.True(t, strings.HasSuffix(s, "- user - subj - 0000-reqid"))

	req, err = http.NewRequest("POST", ts.URL+"/blah", bytes.NewBufferString("1234567890 abcdefg"))
	require.NoError(t, err)
	req.Header.Set("X-Request-ID", "11111-reqid")
	resp, err = clint.Do(req)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	s = lb.buf.String()
	t.Log(s)
	assert.True(t, strings.HasSuffix(s, "- user - subj - 11111-reqid - 1234567890 abcdefg"))
}

func TestLoggerMaxBodySize(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, "1234567890 abcdefg", string(body))
		_, err = w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), WithBody, Log(lb), MaxBodySize(10))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/blah", "", bytes.NewBufferString("1234567890 abcdefg"))
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))

	s := lb.buf.String()
	t.Log(s)
	assert.True(t, strings.Contains(s, "[INFO] REST POST - /blah - 127.0.0.1 - 127.0.0.1 - 200 (9) -"), s)
	assert.True(t, strings.Contains(s, "1234567890..."), s)
}

func TestLoggerDefault(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	ts := httptest.NewServer(Logger(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/blah")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))
}

type mockLgr struct {
	buf bytes.Buffer
}

func (m *mockLgr) Logf(format string, args ...any) {
	_, _ = m.buf.WriteString(fmt.Sprintf(format, args...))
}

func TestGetBody(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/request", strings.NewReader("body"))
	require.Nil(t, err)

	l := New()
	body := l.getBody(req)
	assert.Equal(t, "", body)

	l = New(WithBody)
	body = l.getBody(req)
	assert.Equal(t, "body", body)

	// nil transform reproduces the default path, including the truncation marker
	reqTrunc, err := http.NewRequest("POST", "http://example.com/", strings.NewReader("0123456789abc"))
	require.NoError(t, err)
	l = New(WithBody, MaxBodySize(5), BodyFn(nil))
	assert.Equal(t, "01234...", l.getBody(reqTrunc))

	// a lone carriage return in the raw body is collapsed to a space (single-line guarantee)
	reqCR, err := http.NewRequest("POST", "http://example.com/", strings.NewReader("a\rb"))
	require.NoError(t, err)
	l = New(WithBody)
	assert.Equal(t, "a b", l.getBody(reqCR))
}

func TestGetBodyBodyFn(t *testing.T) {
	// arbitrary (non-json) transform: upper-cases a whole body, or wraps a
	// truncated one with its flag - exercises both the transform and the flag
	fn := func(body string, truncated bool) string {
		if truncated {
			return "<truncated:" + body + ">"
		}
		return strings.ToUpper(body)
	}

	tests := []struct {
		name        string
		body        string
		maxBodySize int
		want        string
	}{
		{"transforms body", "hello world", 1024, "HELLO WORLD"},
		{"plain text, not json", "just text, no braces", 1024, "JUST TEXT, NO BRACES"},
		{"empty body", "", 1024, ""},
		{"collapses transform newlines", "a\nb", 1024, "A B"},
		{"collapses lone carriage return", "a\rb", 1024, "A B"},
		{"collapses unicode line separator", "a\u2028b", 1024, "A B"},
		{"truncated flag set", "0123456789abc", 5, "<truncated:01234>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "http://example.com/", strings.NewReader(tt.body))
			require.NoError(t, err)
			l := New(WithBody, MaxBodySize(tt.maxBodySize), BodyFn(fn))
			assert.Equal(t, tt.want, l.getBody(req))
		})
	}
}

func TestGetBodyBodyFnNoWithBody(t *testing.T) {
	called := false
	fn := func(string, bool) string {
		called = true
		return "should not appear"
	}
	req, err := http.NewRequest("POST", "http://example.com/", strings.NewReader("hello"))
	require.NoError(t, err)

	l := New(BodyFn(fn)) // no WithBody, body logging disabled
	assert.Equal(t, "", l.getBody(req))
	assert.False(t, called, "bodyFn must not run when body logging is disabled")
}

func TestGetBodyBodyFnSkipsEmpty(t *testing.T) {
	called := false
	fn := func(string, bool) string {
		called = true
		return "should not appear" // non-empty even for empty input
	}
	req, err := http.NewRequest("GET", "http://example.com/", http.NoBody)
	require.NoError(t, err)

	l := New(WithBody, BodyFn(fn))
	assert.Equal(t, "", l.getBody(req))
	assert.False(t, called, "bodyFn must not run on an empty body")
}

func TestLoggerBodyFn(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		// downstream handler still receives the original, unmasked body
		assert.Equal(t, `{"user":"alice","password":"secret"}`, string(body))
		_, err = w.Write([]byte("ok"))
		require.NoError(t, err)
	})

	// plain-string masker, deliberately not json-aware, to show the transform
	// need not parse the body
	masker := func(body string, truncated bool) string {
		if truncated {
			return "[body too large]"
		}
		return strings.ReplaceAll(body, "secret", "****")
	}

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), WithBody, Log(lb), BodyFn(masker))
	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/login", "application/json",
		bytes.NewBufferString(`{"user":"alice","password":"secret"}`))
	require.NoError(t, err)
	defer resp.Body.Close() // nolint
	assert.Equal(t, 200, resp.StatusCode)

	s := lb.buf.String()
	t.Log(s)
	assert.Contains(t, s, `{"user":"alice","password":"****"}`)
	assert.NotContains(t, s, "secret")
}

func TestLoggerBodyWithPercent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("ok"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO] REST"), WithBody, Log(lb))
	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	// a body with a percent verb must be logged verbatim, not treated as a format directive
	resp, err := http.Post(ts.URL+"/blah", "", bytes.NewBufferString("a%sb 100%done"))
	require.NoError(t, err)
	defer resp.Body.Close() // nolint
	assert.Equal(t, 200, resp.StatusCode)

	s := lb.buf.String()
	t.Log(s)
	assert.Contains(t, s, "a%sb 100%done")
	assert.NotContains(t, s, "MISSING")
}

func TestLoggerURLCantForgeLogLine(t *testing.T) {
	tests := []struct {
		name string
		esc  string // escaped line-break char in the query
	}{
		{"line feed", "%0A"},
		{"carriage return", "%0D"},
		{"vertical tab", "%0B"},
		{"form feed", "%0C"},
		{"next line", "%C2%85"},
		{"line separator", "%E2%80%A8"},
		{"paragraph separator", "%E2%80%A9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lb := &mockLgr{}
			l := New(Prefix("[INFO] REST"), Log(lb))
			req := httptest.NewRequest("GET", "/x?q="+tt.esc+"[ERROR]%20forged", http.NoBody)
			l.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

			s := lb.buf.String()
			t.Log(s)
			assert.Equal(t, 1, strings.Count(s, "[INFO] REST"), "single log record, no forged one")
			assert.Contains(t, s, "/x?q= [ERROR] forged", "collapsed inline, not dropped")
		})
	}
}

func TestPeek(t *testing.T) {
	cases := []struct {
		body    string
		n       int64
		excerpt string
		hasMore bool
	}{
		{"", -1, "", false},
		{"", 0, "", false},
		{"", 1024, "", false},
		{"123456", -1, "", true},
		{"123456", 0, "", true},
		{"123456", 4, "1234", true},
		{"123456", 5, "12345", true},
		{"123456", 6, "123456", false},
		{"123456", 7, "123456", false},
	}

	for _, c := range cases {
		r, excerpt, hasMore, err := peek(strings.NewReader(c.body), c.n)
		if !assert.NoError(t, err) {
			continue
		}
		body, err := io.ReadAll(r)
		if !assert.NoError(t, err) {
			continue
		}
		assert.Equal(t, c.body, string(body))
		assert.Equal(t, c.excerpt, excerpt)
		assert.Equal(t, c.hasMore, hasMore)
	}

	_, _, _, err := peek(errReader{}, 1024)
	assert.Error(t, err)
}

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func TestSanitizeReqURL(t *testing.T) {
	tbl := []struct {
		in  string
		out string
	}{
		{"", ""},
		{"xyz=123", "xyz=123"},
		{"foo=bar&foo=buzz", "foo=bar&foo=buzz"},
		{"foo=%2&password=1234", "password=********"},
		{"xyz=123&seCret=asdfghjk", "seCret=********&xyz=123"},
		{"xyz=123&secret=asdfghjk&key=val", "key=val&secret=********&xyz=123"},
		{"xyz=123&secret=asdfghjk&key=val&password=1234", "key=val&password=********&secret=********&xyz=123"},
		{"xyz=тест&passwoRD=1234", "passwoRD=********&xyz=тест"},
		{"xyz=тест&password=1234&bar=buzz", "bar=buzz&password=********&xyz=тест"},
		{"xyz=тест&password=пароль&bar=buzz", "bar=buzz&password=********&xyz=тест"},
		{"xyz=тест&password=пароль&bar=buzz&q=?sss?ccc", "bar=buzz&password=********&q=?sss?ccc&xyz=тест"},
	}
	unesc := func(s string) string {
		s, _ = url.QueryUnescape(s)
		return s
	}
	var l *Middleware
	for i, tt := range tbl {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.out, unesc(l.sanitizeQuery(tt.in)), "check #%d, %s", i, tt.in)
		})
	}
}

func TestLoggerApacheCombined(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Log(lb), ApacheCombined,
		IPfn(func(ip string) string {
			return ip + "!masked"
		}),
		UserFn(func(*http.Request) (string, error) {
			return "user", nil
		}),
	)

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/blah?password=secret&key=val&var=123", "", bytes.NewBufferString("1234567890 abcdefg"))
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "blah blah", string(b))

	s := lb.buf.String()
	t.Log(s)
	assert.True(t, strings.HasPrefix(s, "127.0.0.1!masked - user ["))
	assert.True(t, strings.HasSuffix(s, ` "POST /blah?key=val&password=********&var=123 HTTP/1.1" 200 9 "" "Go-http-client/1.1"`), s)
}

func TestAnonymizeIP(t *testing.T) {
	tbl := []struct {
		inp, out string
	}{
		{"12.34.56.78", "12.34.56.0"},
		{"", ""},
		{"", ""},
		{"12.34.56", "12.34.56"},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			assert.Equal(t, tt.out, AnonymizeIP(tt.inp))
		})
	}
}

func TestLogger_WriteHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte("created"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO]"), Log(lb))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	s := lb.buf.String()
	assert.Contains(t, s, "201")
}

func TestLogger_Flush(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("streaming"))
		require.NoError(t, err)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, err = w.Write([]byte(" data"))
		require.NoError(t, err)
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO]"), Log(lb))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "streaming data", string(body))
}

func TestLogger_Hijack(t *testing.T) {
	// hijack requires a real TCP connection, not httptest.ResponseRecorder
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nhijacked"))
	})

	lb := &mockLgr{}
	l := New(Prefix("[INFO]"), Log(lb))

	ts := httptest.NewServer(l.Handler(handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hijacked", string(body))
}

func TestLogger_HijackNotSupported(t *testing.T) {
	// test that hijack returns error when underlying writer doesn't support it
	crw := newCustomResponseWriter(httptest.NewRecorder())
	_, _, err := crw.Hijack()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not implement the Hijacker interface")
}
