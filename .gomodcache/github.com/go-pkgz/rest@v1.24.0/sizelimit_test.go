package rest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSizeLimit(t *testing.T) {

	tbl := []struct {
		method string
		body   string
		code   int
	}{
		{"GET", "", 200},
		{"POST", "1234567", 200},
		{"POST", "1234567890", 200},
		{"POST", "12345678901", 413},
		{"POST", "1234567", 200},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err, "body read failed")
		_, err = w.Write(body)
		require.NoError(t, err, "body write failed")
		dump, _ := httputil.DumpRequest(r, true)
		t.Log(string(dump))
	})

	ts := httptest.NewServer(SizeLimit(10)(handler))
	defer ts.Close()

	for i, tt := range tbl {
		for _, wrap := range []bool{false, true} {
			t.Run(fmt.Sprintf("test-%d/%v", i, wrap), func(t *testing.T) {
				client := http.Client{Timeout: 1 * time.Second}
				var reader io.Reader = strings.NewReader(tt.body)
				if wrap {
					reader = io.NopCloser(reader) // to prevent ContentLength setting up
				}
				req, err := http.NewRequest(tt.method, fmt.Sprintf("%s/%d/%v", ts.URL, i, wrap), reader)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err)
				require.Equal(t, tt.code, resp.StatusCode)

				if resp.StatusCode != http.StatusRequestEntityTooLarge {
					body, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					defer resp.Body.Close()
					assert.Equal(t, tt.body, string(body), "body match")
				}
			})
		}
	}
}
