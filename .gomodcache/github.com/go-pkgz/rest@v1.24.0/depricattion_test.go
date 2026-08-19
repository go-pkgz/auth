package rest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeprecated(t *testing.T) {
	deprecated := Deprecation("1.0.2", time.Date(2020, 9, 1, 18, 32, 0, 0, time.UTC))
	ts := httptest.NewServer(deprecated(getTestHandlerBlah()))
	defer ts.Close()

	u := fmt.Sprintf("%s%s", ts.URL, "/something")

	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", u, http.NoBody)
	require.NoError(t, err)

	r, err := client.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	assert.Equal(t, 200, r.StatusCode)

	assert.Equal(t, `version="1.0.2", date="2020-09-01T18:32:00Z"`, r.Header.Get("Deprecation"))
}
