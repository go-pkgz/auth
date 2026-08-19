package rest

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThrottle(t *testing.T) {

	thrMw := Throttle(10)
	var calls int32
	ts := httptest.NewServer(thrMw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(200 * time.Millisecond)
	})))
	defer ts.Close()

	var okStatus, badStatus int32
	var wg sync.WaitGroup

	wg.Add(100)
	for range 100 {
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL)
			require.NoError(t, err)
			defer resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				atomic.AddInt32(&okStatus, 1)
			case 503:
				atomic.AddInt32(&badStatus, 1)
			default:
				t.Errorf("unexpected status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()

	// two more calls, should pass
	resp, err := http.Get(ts.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	resp, err = http.Get(ts.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, int32(12), atomic.LoadInt32(&calls))
	assert.Equal(t, int32(10), atomic.LoadInt32(&okStatus))
	assert.Equal(t, int32(90), atomic.LoadInt32(&badStatus))
}

func TestThrottleDisabled(t *testing.T) {

	thrMw := Throttle(0)
	var calls int32
	ts := httptest.NewServer(thrMw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(200 * time.Millisecond)
	})))
	defer ts.Close()

	var okStatus, badStatus int32
	var wg sync.WaitGroup

	wg.Add(100)
	for range 100 {
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL)
			require.NoError(t, err)
			defer resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				atomic.AddInt32(&okStatus, 1)
			case 503:
				atomic.AddInt32(&badStatus, 1)
			default:
				t.Errorf("unexpected status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()

	// two more calls, should pass
	resp, err := http.Get(ts.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	resp, err = http.Get(ts.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, int32(102), atomic.LoadInt32(&calls))
	assert.Equal(t, int32(100), atomic.LoadInt32(&okStatus))
	assert.Equal(t, int32(0), atomic.LoadInt32(&badStatus))
}
