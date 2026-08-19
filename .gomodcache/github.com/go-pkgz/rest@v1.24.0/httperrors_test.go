package rest

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendErrorJSON(t *testing.T) {
	l := &mockLgr{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			t.Log("http err request", r.URL)
			SendErrorJSON(w, r, l, 500, errors.New("error 500"), "error details 123456")
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/error")
	require.Nil(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 500, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("content-type"))
	assert.Equal(t, `{"error":"error details 123456"}`+"\n", string(body))
	t.Log(l.buf.String())
}

func TestErrorDetailsMsg(t *testing.T) {
	callerFn := func() {
		req, err := http.NewRequest("GET", "https://example.com/test?k1=v1&k2=v2", http.NoBody)
		require.Nil(t, err)
		req.RemoteAddr = "1.2.3.4"
		msg := errDetailsMsg(req, 500, errors.New("error 500"), "error details 123456")
		assert.Contains(t, msg, "error details 123456 - error 500 - 500 - 1.2.3.4 - https://example."+
			"com/test?k1=v1&k2=v2 [caused by")
		assert.Contains(t, msg, "rest/httperrors_test.go:49 rest.TestErrorDetailsMsg]", msg)

	}
	callerFn()
}

func TestErrorDetailsMsgNoError(t *testing.T) {
	callerFn := func() {
		req, err := http.NewRequest("GET", "https://example.com/test?k1=v1&k2=v2", http.NoBody)
		require.Nil(t, err)
		req.RemoteAddr = "1.2.3.4"
		msg := errDetailsMsg(req, 500, nil, "error details 123456")
		assert.Contains(t, msg, "error details 123456 - no error - 500 - 1.2.3.4 - https://example.com/test?k1=v1&k2=v2 [caused by")
		assert.Contains(t, msg, "rest/httperrors_test.go:61 rest.TestErrorDetailsMsgNoError]", msg)
	}
	callerFn()
}

func TestErrorLogger_Log(t *testing.T) {
	l := &mockLgr{}
	errLogger := NewErrorLogger(l)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			t.Log("http err request", r.URL)
			errLogger.Log(w, r, 500, errors.New("error 500"), "error details 123456")
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/error")
	require.Nil(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 500, resp.StatusCode)

	assert.Equal(t, `{"error":"error details 123456"}`+"\n", string(body))
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("content-type"))

	t.Log(l.buf.String())
}
