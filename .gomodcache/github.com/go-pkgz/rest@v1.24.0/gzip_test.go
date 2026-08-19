package rest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGzipCustom(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Lorem Ipsum is simply dummy text of the printing and typesetting industry. " +
			"Lorem Ipsum has been the industry’s standard dummy text ever since the 1500s, when an unknown printer took " +
			"a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries," +
			" but also the leap into electronic typesetting, remaining essentially unchanged. It was popularized" +
			" in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, " +
			"and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip("text/plain", "text/html")(handler))
	defer ts.Close()

	client := http.Client{}

	{
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, 357, len(b), "compressed size")

		gzr, err := gzip.NewReader(bytes.NewBuffer(b))
		require.NoError(t, err)
		b, err = io.ReadAll(gzr)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(b), "Lorem Ipsum"), string(b))
	}

	{
		// the request content type has no say in the decision, the response is what counts
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Content-Type", "something")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, 357, len(b), "compressed size")
	}

}

func TestGzipVary(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(strings.Repeat("compress me. ", 50)))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	tbl := []struct {
		name           string
		acceptEncoding string
		encoded        bool
	}{
		{"gzip accepted", "gzip", true},
		{"gzip not accepted", "", false},
		{"other encoding", "br", false},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "text/plain")
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			} else {
				req.Header.Set("Accept-Encoding", "identity")
			}

			resp, err := http.DefaultTransport.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// caches must be told the body varies by Accept-Encoding whether or not it got compressed
			assert.Contains(t, resp.Header.Values("Vary"), "Accept-Encoding")
			if tt.encoded {
				assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
				return
			}
			assert.Empty(t, resp.Header.Get("Content-Encoding"))
		})
	}
}

func TestGzipWriteHeader(t *testing.T) {
	// test that explicit WriteHeader call works with gzip middleware
	longText := strings.Repeat("This is a test message for gzip compression. ", 20)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte(longText))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	client := http.Client{}
	req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// verify it's compressed (smaller than original)
	assert.Less(t, len(b), len(longText), "response should be compressed")

	gzr, err := gzip.NewReader(bytes.NewBuffer(b))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(gzr)
	require.NoError(t, err)
	assert.Equal(t, longText, string(decompressed))
}

func TestGzipDefault(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Lorem Ipsum is simply dummy text of the printing and typesetting industry. " +
			"Lorem Ipsum has been the industry’s standard dummy text ever since the 1500s, when an unknown printer took " +
			"a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries," +
			" but also the leap into electronic typesetting, remaining essentially unchanged. It was popularized" +
			" in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, " +
			"and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	client := http.Client{}

	{
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, 357, len(b), "compressed size")

		gzr, err := gzip.NewReader(bytes.NewBuffer(b))
		require.NoError(t, err)
		b, err = io.ReadAll(gzr)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(b), "Lorem Ipsum"), string(b))
	}

	{
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.Nil(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, 576, len(b), "uncompressed size")
	}

	{
		// the request content type has no say in the decision, the response is what counts
		req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Content-Type", "something")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, 357, len(b), "compressed size")
	}

}

func TestGzipResponseContentType(t *testing.T) {
	body := strings.Repeat("compress me if the response type says so. ", 40)

	tbl := []struct {
		name        string
		respType    string // set by the handler, empty means let it be sniffed
		reqType     string // request content type, must not influence the outcome
		wantEncoded bool
	}{
		{name: "json response", respType: "application/json", wantEncoded: true},
		{name: "html response", respType: "text/html; charset=utf-8", wantEncoded: true},
		{name: "octet-stream response", respType: "application/octet-stream", wantEncoded: false},
		{name: "image response", respType: "image/png", wantEncoded: false},
		{name: "sniffed as text", respType: "", wantEncoded: true},
		{name: "json response, misleading request type", respType: "application/json", reqType: "image/png", wantEncoded: true},
		{name: "binary response, misleading request type", respType: "image/png", reqType: "application/json", wantEncoded: false},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.respType != "" {
					w.Header().Set("Content-Type", tt.respType)
				}
				_, err := w.Write([]byte(body))
				require.NoError(t, err)
			})
			ts := httptest.NewServer(Gzip()(handler))
			defer ts.Close()

			req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Accept-Encoding", "gzip")
			if tt.reqType != "" {
				req.Header.Set("Content-Type", tt.reqType)
			}

			resp, err := http.DefaultTransport.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Contains(t, resp.Header.Values("Vary"), "Accept-Encoding")
			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			if !tt.wantEncoded {
				assert.Empty(t, resp.Header.Get("Content-Encoding"))
				assert.Equal(t, body, string(raw))
				return
			}

			require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
			assert.Less(t, len(raw), len(body), "compressed payload should be smaller")
			gzr, err := gzip.NewReader(bytes.NewReader(raw))
			require.NoError(t, err)
			decoded, err := io.ReadAll(gzr)
			require.NoError(t, err)
			assert.Equal(t, body, string(decoded))
		})
	}
}

func TestGzipAcceptEncoding(t *testing.T) {
	tbl := []struct {
		header string
		want   bool
	}{
		{"gzip", true},
		{"", false},
		{"identity", false},
		{"br", false},
		{"br, gzip", true},
		{"gzip;q=0.8", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"*", true},
		{"*;q=0", false},
		{"deflate, gzip;q=1.0, *;q=0.5", true},
		{"GZIP", true},
		{"gzip;q=0, *;q=1", false},
		{"*;q=1, gzip;q=0", false},
		{"*;q=0, gzip", true},
		{"*;q=0, gzip;q=1", true},
		{"br;q=1, *;q=0", false},
	}

	for _, tt := range tbl {
		t.Run(tt.header, func(t *testing.T) {
			assert.Equal(t, tt.want, acceptsGzip([]string{tt.header}))
		})
	}
}

func TestGzipNoBodyStatuses(t *testing.T) {
	tbl := []struct {
		name   string
		status int
	}{
		{"no content", http.StatusNoContent},
		{"not modified", http.StatusNotModified},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
			})
			ts := httptest.NewServer(Gzip()(handler))
			defer ts.Close()

			req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Accept-Encoding", "gzip")

			resp, err := http.DefaultTransport.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.status, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Content-Encoding"), "bodyless response should not be compressed")
		})
	}
}

func TestGzipStreaming(t *testing.T) {
	// a handler that flushes between chunks must keep working through the compressor
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := range 3 {
			_, err := fmt.Fprintf(w, "chunk-%d\n", i)
			require.NoError(t, err)
			w.(http.Flusher).Flush()
		}
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/stream", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	gzr, err := gzip.NewReader(resp.Body)
	require.NoError(t, err)
	decoded, err := io.ReadAll(gzr)
	require.NoError(t, err)
	assert.Equal(t, "chunk-0\nchunk-1\nchunk-2\n", string(decoded))
}

func TestGzipEmptyBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// the status has to reach the client even though the handler wrote no body
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzr, err := gzip.NewReader(bytes.NewReader(b))
		require.NoError(t, err)
		b, err = io.ReadAll(gzr)
		require.NoError(t, err)
	}
	assert.Empty(t, b)
}

func TestGzipContentLengthDropped(t *testing.T) {
	body := strings.Repeat("x", 500)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	assert.NotEqual(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"),
		"the uncompressed length must not survive onto a compressed body")
}

func TestGzipWriterInterfaces(t *testing.T) {
	t.Run("hijack passes through and suppresses the deferred write", func(t *testing.T) {
		done := make(chan error, 1)
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			h, ok := w.(http.Hijacker)
			if !ok {
				done <- errors.New("the wrapper must offer Hijack")
				return
			}
			conn, _, err := h.Hijack()
			if err != nil {
				done <- err
				return
			}
			// once hijacked nothing may write a status to the connection, including the deferred close
			_ = conn.Close()
			done <- nil
		})
		ts := httptest.NewServer(Gzip()(handler))
		defer ts.Close()

		req, err := http.NewRequest("GET", ts.URL+"/upgrade", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		//nolint:bodyclose // the handler hijacks and closes the connection, there is no response to close
		_, err = http.DefaultTransport.RoundTrip(req)
		require.Error(t, err, "hijacked connection yields no response")
		require.NoError(t, <-done)
	})

	t.Run("hijack unsupported by the underlying writer", func(t *testing.T) {
		gw := &gzipResponseWriter{ResponseWriter: httptest.NewRecorder(), gzCts: gzDefaultContentTypes}
		_, _, err := gw.hijack()
		assert.Error(t, err)
	})

	t.Run("unwrap returns the underlying writer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		gw := &gzipResponseWriter{ResponseWriter: rec, gzCts: gzDefaultContentTypes}
		assert.Same(t, rec, gw.Unwrap())
	})

	t.Run("repeated WriteHeader ignored", func(t *testing.T) {
		rec := httptest.NewRecorder()
		gw := &gzipResponseWriter{ResponseWriter: rec, gzCts: gzDefaultContentTypes}
		gw.Header().Set("Content-Type", "text/plain")
		gw.WriteHeader(http.StatusTeapot)
		gw.WriteHeader(http.StatusOK)
		gw.close(true)
		assert.Equal(t, http.StatusTeapot, rec.Code)
	})

	t.Run("flush without a body commits the status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		gw := &gzipResponseWriter{ResponseWriter: rec, gzCts: gzDefaultContentTypes}
		gw.flush()
		gw.close(true)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestGzipSkipsAlreadyEncoded(t *testing.T) {
	// a handler that encoded the body itself must not be wrapped a second time
	payload := []byte("pretend this is brotli")
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "br")
		_, err := w.Write(payload)
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/asset", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "br", resp.Header.Get("Content-Encoding"))
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, b, "body must be passed through untouched")
}

func TestGzipSkipsPartialContent(t *testing.T) {
	body := strings.Repeat("range me. ", 60)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Range", "bytes 0-599/1200")
		w.WriteHeader(http.StatusPartialContent)
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/ranged", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Range", "bytes=0-599")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
	// the range offsets describe the uncompressed representation, compressing would invalidate them
	assert.Empty(t, resp.Header.Get("Content-Encoding"))
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(b))
}

func TestGzipFlushBeforeWrite(t *testing.T) {
	// flushing before any write commits the headers, so the decision has to be settled by then
	body := strings.Repeat("late text. ", 50)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush() // no Content-Type set yet
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/flush-first", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// whatever was decided, the body has to match what the headers advertise
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzr, err := gzip.NewReader(bytes.NewReader(raw))
		require.NoError(t, err)
		raw, err = io.ReadAll(gzr)
		require.NoError(t, err)
	}
	assert.Equal(t, body, string(raw), "body must decode according to the advertised encoding")
}

func TestGzipFirstStatusWins(t *testing.T) {
	rec := httptest.NewRecorder()
	gw := &gzipResponseWriter{ResponseWriter: rec, gzCts: gzDefaultContentTypes}

	// no Content-Type, so the first call cannot commit yet, but it still fixes the status
	gw.WriteHeader(http.StatusTeapot)
	gw.WriteHeader(http.StatusOK)
	gw.close(true)

	assert.Equal(t, http.StatusTeapot, rec.Code)
}

func TestGzipInterimResponse(t *testing.T) {
	body := strings.Repeat("after early hints. ", 40)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints) // interim, the real status still follows
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/hints", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "the interim status must not become the final one")
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzr, err := gzip.NewReader(bytes.NewReader(raw))
		require.NoError(t, err)
		raw, err = io.ReadAll(gzr)
		require.NoError(t, err)
	}
	assert.Equal(t, body, string(raw))
}

func TestGzipAcceptEncodingRepeatedFields(t *testing.T) {
	tbl := []struct {
		name    string
		headers []string
		want    bool
	}{
		{"no fields", nil, false},
		{"gzip in the second field", []string{"br", "gzip"}, true},
		{"refusal in a later field beats an earlier wildcard", []string{"*;q=1", "gzip;q=0"}, false},
		{"acceptance in a later field beats an earlier wildcard refusal", []string{"*;q=0", "gzip"}, true},
		{"wildcard only, split across fields", []string{"br", "*"}, true},
		{"nothing acceptable", []string{"br", "deflate"}, false},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, acceptsGzip(tt.headers))
		})
	}
}

func TestGzipRepeatedAcceptEncodingOverWire(t *testing.T) {
	body := strings.Repeat("no gzip please. ", 50)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	})
	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/split", http.NoBody)
	require.NoError(t, err)
	// two fields are one list, and the named gzip refusal has to win over the wildcard
	req.Header.Add("Accept-Encoding", "*;q=1")
	req.Header.Add("Accept-Encoding", "gzip;q=0")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Empty(t, resp.Header.Get("Content-Encoding"))
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(b))
}

func TestGzipPanicLeavesResponseUncommitted(t *testing.T) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})
	l := &mockLgr{}
	// Recoverer sits outside Gzip, so it can only send a 500 while the response is uncommitted
	ts := httptest.NewServer(Recoverer(l)(Gzip()(handler)))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/panics", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a panicking handler must not be committed as 200 by the gzip wrapper")
}

func TestGzipNoBodyAndUpgradeStatuses(t *testing.T) {
	tbl := []struct {
		name   string
		status int
	}{
		{"reset content", http.StatusResetContent},
		{"no content", http.StatusNoContent},
		{"not modified", http.StatusNotModified},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
			})
			ts := httptest.NewServer(Gzip()(handler))
			defer ts.Close()

			req, err := http.NewRequest("GET", ts.URL+"/x", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Accept-Encoding", "gzip")

			resp, err := http.DefaultTransport.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.status, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Content-Encoding"), "a status without content must not be compressed")
		})
	}
}

func TestGzipSwitchingProtocolsIsFinal(t *testing.T) {
	// 101 hands the connection over, it must not be treated as an interim 1xx
	rec := httptest.NewRecorder()
	gw := &gzipResponseWriter{ResponseWriter: rec, gzCts: gzDefaultContentTypes}
	gw.Header().Set("Content-Type", "text/plain")
	gw.WriteHeader(http.StatusSwitchingProtocols)
	gw.close(true)

	assert.Equal(t, http.StatusSwitchingProtocols, rec.Code)
	assert.Empty(t, rec.Header().Get("Content-Encoding"), "an upgraded connection must not be gzipped")
}

func TestGzipNoSniffWhenAlreadyEncoded(t *testing.T) {
	// net/http suppresses sniffing for an encoded body, a guessed type would just mislabel it
	rec := httptest.NewRecorder()
	gw := &gzipResponseWriter{ResponseWriter: rec, gzCts: gzDefaultContentTypes}
	gw.Header().Set("Content-Encoding", "br")

	_, err := gw.Write([]byte("plain looking text that would sniff as text/plain"))
	require.NoError(t, err)
	gw.close(true)

	assert.Empty(t, rec.Header().Get("Content-Type"), "no content type should be guessed from encoded bytes")
	assert.Equal(t, "br", rec.Header().Get("Content-Encoding"))
}

func TestGzipWriterCapabilitiesMatchUnderlying(t *testing.T) {
	body := strings.Repeat("stream me. ", 40)

	tbl := []struct {
		name         string
		wrap         func(http.Handler) http.Handler
		wantFlusher  bool
		wantHijacker bool
	}{
		{
			name:         "plain server writer",
			wrap:         func(h http.Handler) http.Handler { return h },
			wantFlusher:  true,
			wantHijacker: true,
		},
		{
			// http.TimeoutHandler offers neither, so the wrapper must not claim them either
			name:         "behind Timeout",
			wrap:         Timeout(time.Minute),
			wantFlusher:  false,
			wantHijacker: false,
		},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			var gotFlusher, gotHijacker bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, gotFlusher = w.(http.Flusher)
				_, gotHijacker = w.(http.Hijacker)
				w.Header().Set("Content-Type", "text/plain")
				_, err := w.Write([]byte(body))
				require.NoError(t, err)
			})

			ts := httptest.NewServer(tt.wrap(Gzip()(handler)))
			defer ts.Close()

			req, err := http.NewRequest("GET", ts.URL+"/x", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Accept-Encoding", "gzip")

			resp, err := http.DefaultTransport.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			_, err = io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, tt.wantFlusher, gotFlusher, "Flusher must be advertised only when it works")
			assert.Equal(t, tt.wantHijacker, gotHijacker, "Hijacker must be advertised only when it works")
		})
	}
}

func TestGzipSwitchingProtocolsWithoutContentType(t *testing.T) {
	// the plain upgrade sequence: 101 with no content type, then the handler takes the connection.
	// the status has to be on the wire before Hijack, or it is never sent at all
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Upgrade", "foo")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)

		hj, ok := w.(http.Hijacker)
		require.True(t, ok, "upgrade needs a Hijacker")
		conn, buf, err := hj.Hijack()
		require.NoError(t, err)
		defer conn.Close()

		_, err = buf.WriteString("raw-protocol-bytes")
		require.NoError(t, err)
		require.NoError(t, buf.Flush())
	})

	ts := httptest.NewServer(Gzip()(handler))
	defer ts.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprint(conn, "GET /upgrade HTTP/1.1\r\nHost: example.com\r\n"+
		"Accept-Encoding: gzip\r\nUpgrade: foo\r\nConnection: Upgrade\r\n\r\n")
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	got, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Contains(t, string(got), "101 Switching Protocols", "the 101 status line must reach the client")
	assert.Contains(t, string(got), "raw-protocol-bytes")
	assert.NotContains(t, string(got), "Content-Encoding: gzip", "an upgraded connection must not be gzipped")
}

// hijackStub is a ResponseWriter whose Hijack and Write can be made to fail on demand
type hijackStub struct {
	http.ResponseWriter
	hijackErr error
	writeErr  error
	written   bytes.Buffer
}

func (h *hijackStub) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.hijackErr != nil {
		return nil, nil, h.hijackErr
	}
	return nil, nil, nil
}

func (h *hijackStub) Write(b []byte) (int, error) {
	if h.writeErr != nil {
		return 0, h.writeErr
	}
	return h.written.Write(b)
}

func TestGzipHijackErrorPath(t *testing.T) {
	t.Run("failing stream close is reported, not swallowed", func(t *testing.T) {
		stub := &hijackStub{ResponseWriter: httptest.NewRecorder()}
		gw := &gzipResponseWriter{ResponseWriter: stub, gzCts: gzDefaultContentTypes}
		gw.Header().Set("Content-Type", "text/plain")

		_, err := gw.Write([]byte(strings.Repeat("compress me. ", 40)))
		require.NoError(t, err)
		require.NotNil(t, gw.gz, "the stream has to be open for this case to mean anything")

		boom := errors.New("write failed")
		stub.writeErr = boom // the flush inside gz.Close now fails

		_, _, err = gw.hijack()
		require.Error(t, err, "a truncated stream must not be hidden behind a successful hijack")
		assert.ErrorIs(t, err, boom)
		assert.False(t, gw.hijacked)
	})

	t.Run("failed hijack leaves the stream attached so writes error instead of corrupting", func(t *testing.T) {
		nope := errors.New("already hijacked")
		stub := &hijackStub{ResponseWriter: httptest.NewRecorder(), hijackErr: nope}
		gw := &gzipResponseWriter{ResponseWriter: stub, gzCts: gzDefaultContentTypes}
		gw.Header().Set("Content-Type", "text/plain")

		_, err := gw.Write([]byte(strings.Repeat("compress me. ", 40)))
		require.NoError(t, err)

		_, _, err = gw.hijack()
		require.ErrorIs(t, err, nope)

		assert.False(t, gw.hijacked, "the connection was never taken over")
		require.NotNil(t, gw.gz, "the writer stays attached so a further write cannot bypass it")
		assert.Equal(t, "gzip", gw.Header().Get("Content-Encoding"))

		// the response already advertises gzip, so raw bytes must not be appended to it
		_, err = gw.Write([]byte("RAW-AFTER-FAILED-HIJACK"))
		require.Error(t, err, "writing after a failed hijack has to fail rather than corrupt the body")
		assert.NotContains(t, stub.written.String(), "RAW-AFTER-FAILED-HIJACK")

		// the deferred close still returns the writer to the pool
		gw.close(true)
		assert.Nil(t, gw.gz)
	})

	t.Run("successful hijack releases the writer", func(t *testing.T) {
		stub := &hijackStub{ResponseWriter: httptest.NewRecorder()}
		gw := &gzipResponseWriter{ResponseWriter: stub, gzCts: gzDefaultContentTypes}
		gw.Header().Set("Content-Type", "text/plain")

		_, err := gw.Write([]byte(strings.Repeat("compress me. ", 40)))
		require.NoError(t, err)

		_, _, err = gw.hijack()
		require.NoError(t, err)
		assert.True(t, gw.hijacked)
		assert.Nil(t, gw.gz, "the writer goes back to the pool once the connection is taken over")
	})
}
