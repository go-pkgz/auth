package rest

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBenchmark_Stats(t *testing.T) {
	bench := NewBenchmarks()
	bench.update(time.Millisecond * 50)
	bench.update(time.Millisecond * 150)
	bench.update(time.Millisecond * 250)
	bench.update(time.Millisecond * 100)

	{
		res := bench.Stats(time.Minute)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 4, RequestsSec: 4, AverageRespTime: 137500,
			MinRespTime: (time.Millisecond * 50).Microseconds(), MaxRespTime: (time.Millisecond * 250).Microseconds()}, res)
	}

	{
		res := bench.Stats(time.Second * 5)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 4, RequestsSec: 4, AverageRespTime: 137500,
			MinRespTime: (time.Millisecond * 50).Microseconds(), MaxRespTime: (time.Millisecond * 250).Microseconds()}, res)
	}

	{
		res := bench.Stats(time.Millisecond * 999)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{}, res)
	}
}

func TestBenchmark_Stats2s(t *testing.T) {
	bench := NewBenchmarks()
	bench.update(time.Millisecond * 50)
	bench.update(time.Millisecond * 150)
	bench.update(time.Millisecond * 250)
	time.Sleep(time.Second)
	bench.update(time.Millisecond * 100)

	res := bench.Stats(time.Minute)
	t.Logf("%+v", res)
	assert.Equal(t, BenchmarkStats{Requests: 4, RequestsSec: 2, AverageRespTime: 137500,
		MinRespTime: (time.Millisecond * 50).Microseconds(), MaxRespTime: (time.Millisecond * 250).Microseconds()}, res)
}

func TestBenchmark_WithTimeRange(t *testing.T) {

	nowFn := func(dt time.Time) func() time.Time {
		return func() time.Time { return dt }
	}

	{
		bench := NewBenchmarks().WithTimeRange(time.Minute)

		bench.nowFn = nowFn(time.Date(2018, time.January, 1, 0, 0, 0, 0, time.UTC))
		bench.update(time.Millisecond * 50)
		bench.update(time.Millisecond * 150)
		bench.update(time.Millisecond * 250)
		bench.update(time.Millisecond * 100)

		bench.nowFn = nowFn(time.Date(2018, time.January, 1, 1, 0, 0, 0, time.UTC)) // 1 hour later
		bench.update(time.Millisecond * 1000)

		res := bench.Stats(time.Minute)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 1, RequestsSec: 1, AverageRespTime: 1000000,
			MinRespTime: (time.Millisecond * 1000).Microseconds(), MaxRespTime: (time.Millisecond * 1000).Microseconds()}, res)

		res = bench.Stats(time.Hour)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 1, RequestsSec: 1, AverageRespTime: 1000000,
			MinRespTime: (time.Millisecond * 1000).Microseconds(), MaxRespTime: (time.Millisecond * 1000).Microseconds()}, res)
	}

	{
		bench := NewBenchmarks().WithTimeRange(time.Hour * 2)

		bench.nowFn = nowFn(time.Date(2018, time.January, 1, 0, 0, 0, 0, time.UTC))
		bench.update(time.Millisecond * 50)
		bench.update(time.Millisecond * 150)
		bench.update(time.Millisecond * 250)
		bench.update(time.Millisecond * 100)

		bench.nowFn = nowFn(time.Date(2018, time.January, 1, 1, 0, 0, 0, time.UTC)) // 1 hour later
		bench.update(time.Millisecond * 1000)

		res := bench.Stats(time.Minute)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 1, RequestsSec: 1, AverageRespTime: 1000000,
			MinRespTime: (time.Millisecond * 1000).Microseconds(), MaxRespTime: (time.Millisecond * 1000).Microseconds()}, res)

		res = bench.Stats(time.Hour)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 5, RequestsSec: 0.0013885031935573452, AverageRespTime: 310000,
			MinRespTime: (time.Millisecond * 50).Microseconds(), MaxRespTime: (time.Millisecond * 1000).Microseconds()}, res)
	}
}

func TestBenchmark_Cleanup(t *testing.T) {
	bench := NewBenchmarks()
	for i := range 1000 {
		bench.nowFn = func() time.Time {
			return time.Date(2022, 5, 15, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second) // every 2s fake time
		}
		bench.update(time.Millisecond * 50)
	}

	{
		res := bench.Stats(time.Hour)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 900, RequestsSec: 1, AverageRespTime: 50000,
			MinRespTime: (time.Millisecond * 50).Microseconds(), MaxRespTime: (time.Millisecond * 50).Microseconds()}, res)
	}
	{
		res := bench.Stats(time.Minute)
		t.Logf("%+v", res)
		assert.Equal(t, BenchmarkStats{Requests: 60, RequestsSec: 1, AverageRespTime: 50000,
			MinRespTime: (time.Millisecond * 50).Microseconds(), MaxRespTime: (time.Millisecond * 50).Microseconds()}, res)
	}

	assert.Equal(t, 900, bench.data.Len())
}

// fakeClock drives Benchmarks without waiting on wall time
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestBenchmarks_Handler(t *testing.T) {
	const reqDuration = 50 * time.Millisecond

	clk := &fakeClock{t: time.Date(2022, 5, 15, 0, 0, 0, 0, time.UTC)}
	bench := NewBenchmarks()
	bench.nowFn = clk.now

	// the handler burns fake time instead of sleeping, so every request measures exactly reqDuration
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		clk.advance(reqDuration)
		_, err := w.Write([]byte("blah blah"))
		require.NoError(t, err)
	})

	ts := httptest.NewServer(bench.Handler(handler))
	defer ts.Close()

	for range 100 {
		resp, err := ts.Client().Get(ts.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}

	// 100 requests of 50ms cover 5s of fake time, landing in six one-second buckets
	const wantRespTime = int64(50000) // microseconds
	wantRate := 100.0 / 6.0

	for _, interval := range []time.Duration{time.Minute, 15 * time.Minute} {
		t.Run(interval.String(), func(t *testing.T) {
			res := bench.Stats(interval)
			t.Logf("%+v", res)
			assert.Equal(t, 100, res.Requests)
			assert.InDelta(t, wantRate, res.RequestsSec, 0.001)
			assert.Equal(t, wantRespTime, res.AverageRespTime)
			assert.Equal(t, wantRespTime, res.MinRespTime)
			assert.Equal(t, wantRespTime, res.MaxRespTime)
		})
	}
}

func TestBenchmark_ConcurrentAccess(t *testing.T) {
	bench := NewBenchmarks()
	var wg sync.WaitGroup

	// simulate concurrent updates
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bench.update(time.Duration(i) * time.Millisecond)
		}(i)
	}

	// simulate concurrent stats reads while updating
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats := bench.Stats(time.Minute)
			require.GreaterOrEqual(t, stats.Requests, 0)
		}()
	}

	wg.Wait()

	stats := bench.Stats(time.Minute)
	assert.Equal(t, 100, stats.Requests)
}

func TestBenchmark_EdgeCases(t *testing.T) {
	bench := NewBenchmarks()

	t.Run("zero duration", func(t *testing.T) {
		bench.update(0)
		stats := bench.Stats(time.Minute)
		assert.Equal(t, int64(0), stats.MinRespTime)
		assert.Equal(t, int64(0), stats.MaxRespTime)
	})

	t.Run("very large duration", func(t *testing.T) {
		bench.update(time.Hour)
		stats := bench.Stats(time.Minute)
		assert.Equal(t, time.Hour.Microseconds(), stats.MaxRespTime)
	})

	t.Run("negative stats interval", func(t *testing.T) {
		stats := bench.Stats(-time.Minute)
		assert.Equal(t, BenchmarkStats{}, stats)
	})
}

func TestBenchmark_TimeWindowBoundaries(t *testing.T) {
	bench := NewBenchmarks()
	now := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

	bench.nowFn = func() time.Time { return now }

	// add data points exactly at minute boundaries
	for i := range 120 {
		bench.nowFn = func() time.Time {
			return now.Add(time.Duration(i) * time.Second)
		}
		bench.update(time.Millisecond * 50)
	}

	tests := []struct {
		name     string
		interval time.Duration
		want     int // expected number of requests
	}{
		{"exact minute", time.Minute, 60},
		{"30 seconds", time.Second * 30, 30},
		{"90 seconds", time.Second * 90, 90},
		{"2 minutes", time.Minute * 2, 120},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := bench.Stats(tt.interval)
			assert.Equal(t, tt.want, stats.Requests, "interval %v should have %d requests", tt.interval, tt.want)
		})
	}
}

func TestBenchmark_CustomTimeRange(t *testing.T) {
	tests := []struct {
		name       string
		timeRange  time.Duration
		dataPoints int
		wantKept   int
	}{
		{"1 minute range", time.Minute, 120, 60},
		{"5 minute range", time.Minute * 5, 400, 300},
		{"custom 45s range", time.Second * 45, 100, 45},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bench := NewBenchmarks().WithTimeRange(tt.timeRange)
			now := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

			// add data points
			for i := 0; i < tt.dataPoints; i++ {
				bench.nowFn = func() time.Time {
					return now.Add(time.Duration(i) * time.Second)
				}
				bench.update(time.Millisecond * 50)
			}

			assert.Equal(t, tt.wantKept, bench.data.Len(),
				"should keep only %d data points for %v time range",
				tt.wantKept, tt.timeRange)
		})
	}
}

func TestBenchmark_VariableLoad(t *testing.T) {
	bench := NewBenchmarks()
	now := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

	// simulate variable load pattern
	patterns := []struct {
		count    int
		duration time.Duration
	}{
		{10, time.Millisecond * 10},  // fast responses
		{5, time.Millisecond * 100},  // medium responses
		{2, time.Millisecond * 1000}, // slow responses
	}

	for i, p := range patterns {
		bench.nowFn = func() time.Time {
			return now.Add(time.Duration(i) * time.Second)
		}
		for j := 0; j < p.count; j++ {
			bench.update(p.duration)
		}
	}

	stats := bench.Stats(time.Minute)
	assert.Equal(t, 17, stats.Requests)                  // total requests across all patterns
	assert.Equal(t, int64(1000*1000), stats.MaxRespTime) // should be the max (1000ms = 1_000_000 microseconds)
	assert.Equal(t, int64(10*1000), stats.MinRespTime)   // should be the min (10ms = 10_000 microseconds)
}
