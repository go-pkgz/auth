package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoCache(t *testing.T) {

	rr := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Logf("%+v", r)
	})

	handler := NoCache(testHandler)
	req, err := http.NewRequest("GET", "/api/v1/params", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("ETag", "123")
	req.Header.Set("If-None-Match", "xyz")
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, "Thu, 01 Jan 1970 00:00:00 UTC", rr.Header().Get("Expires"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
}
