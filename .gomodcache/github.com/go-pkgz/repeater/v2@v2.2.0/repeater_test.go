package repeater

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepeater(t *testing.T) {
	t.Run("zero or negative attempts converted to 1", func(t *testing.T) {
		r := NewFixed(0, time.Millisecond)
		assert.Equal(t, 1, r.attempts)
		r = NewFixed(-1, time.Millisecond)
		assert.Equal(t, 1, r.attempts)
	})

	t.Run("nil strategy defaults to fixed 1s", func(t *testing.T) {
		r := NewWithStrategy(1, nil)
		s, ok := r.strategy.(FixedDelay)
		require.True(t, ok)
		assert.Equal(t, time.Second, s.Delay)
	})
}

func TestDo(t *testing.T) {
	t.Run("success first try", func(t *testing.T) {
		calls := 0
		r := NewFixed(3, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("success after retries", func(t *testing.T) {
		calls := 0
		r := NewFixed(3, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			if calls < 3 {
				return errors.New("not yet")
			}
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 3, calls)
	})

	t.Run("failure after all attempts", func(t *testing.T) {
		calls := 0
		r := NewFixed(3, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			return errors.New("always fails")
		})
		require.Error(t, err)
		assert.Equal(t, "always fails", err.Error())
		assert.Equal(t, 3, calls)
	})

	t.Run("stops on critical error", func(t *testing.T) {
		calls := 0
		criticalErr := errors.New("critical")
		r := NewFixed(5, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			return criticalErr
		}, criticalErr)
		require.ErrorIs(t, err, criticalErr)
		assert.Equal(t, 1, calls)
	})

	t.Run("stops on wrapped critical error", func(t *testing.T) {
		calls := 0
		criticalErr := errors.New("critical")
		r := NewFixed(5, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			return errors.Join(errors.New("wrapped"), criticalErr)
		}, criticalErr)
		require.ErrorIs(t, err, criticalErr)
		assert.Equal(t, 1, calls)
	})
}

func TestErrorClassifier(t *testing.T) {
	t.Run("classifier stops on non-retryable error", func(t *testing.T) {
		calls := 0
		classifier := func(err error) bool {
			return err.Error() != "stop"
		}

		r := NewBackoff(5, time.Millisecond)
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			return errors.New("stop")
		})

		require.Error(t, err)
		assert.Equal(t, "stop", err.Error())
		assert.Equal(t, 1, calls)
	})

	t.Run("classifier retries on retryable error", func(t *testing.T) {
		calls := 0
		classifier := func(err error) bool {
			return err.Error() == "retry"
		}

		r := NewBackoff(3, time.Millisecond)
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			if calls < 3 {
				return errors.New("retry")
			}
			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, 3, calls)
	})

	t.Run("classifier with mixed errors", func(t *testing.T) {
		calls := 0
		classifier := func(err error) bool {
			return err.Error() != "401"
		}

		r := NewBackoff(5, time.Millisecond)
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			switch calls {
			case 1:
				return errors.New("429") // retryable
			case 2:
				return errors.New("503") // retryable
			case 3:
				return errors.New("401") // non-retryable
			default:
				return nil
			}
		})

		require.Error(t, err)
		assert.Equal(t, "401", err.Error())
		assert.Equal(t, 3, calls)
	})

	t.Run("classifier takes precedence over critical errors", func(t *testing.T) {
		calls := 0
		criticalErr := errors.New("critical")
		classifier := func(err error) bool {
			return true // always retry
		}

		r := NewBackoff(3, time.Millisecond)
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			if calls < 3 {
				return criticalErr
			}
			return nil
		}, criticalErr) // this should be ignored due to classifier

		require.NoError(t, err)
		assert.Equal(t, 3, calls)
	})

	t.Run("no classifier falls back to critical errors", func(t *testing.T) {
		calls := 0
		criticalErr := errors.New("critical")

		r := NewBackoff(5, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			return criticalErr
		}, criticalErr)

		require.ErrorIs(t, err, criticalErr)
		assert.Equal(t, 1, calls)
	})

	t.Run("classifier with nil error", func(t *testing.T) {
		calls := 0
		classifierCalls := 0
		classifier := func(err error) bool {
			classifierCalls++
			return err != nil
		}

		r := NewBackoff(3, time.Millisecond)
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, 1, calls)
		assert.Equal(t, 0, classifierCalls) // classifier should not be called on success
	})

	t.Run("api client example", func(t *testing.T) {
		calls := 0
		isRetryable := func(err error) bool {
			if err == nil {
				return false
			}
			errStr := err.Error()
			// retryable errors
			if errStr == "429" || errStr == "503" || errStr == "timeout" {
				return true
			}
			// non-retryable errors
			if errStr == "401" || errStr == "400" {
				return false
			}
			return true // default to retry
		}

		r := NewBackoff(5, time.Millisecond)
		r.SetErrorClassifier(isRetryable)
		err := r.Do(context.Background(), func() error {
			calls++
			switch calls {
			case 1:
				return errors.New("429") // rate limit - retry
			case 2:
				return errors.New("timeout") // timeout - retry
			case 3:
				return errors.New("401") // auth error - stop
			default:
				return nil
			}
		})

		require.Error(t, err)
		assert.Equal(t, "401", err.Error())
		assert.Equal(t, 3, calls)
	})

	t.Run("classifier works with NewFixed", func(t *testing.T) {
		calls := 0
		classifier := func(err error) bool {
			return err.Error() != "stop"
		}

		r := NewFixed(5, time.Millisecond)
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			if calls < 3 {
				return errors.New("retry")
			}
			return errors.New("stop")
		})

		require.Error(t, err)
		assert.Equal(t, "stop", err.Error())
		assert.Equal(t, 3, calls)
	})

	t.Run("classifier works with NewWithStrategy", func(t *testing.T) {
		calls := 0
		classifier := func(err error) bool {
			return err.Error() == "retry"
		}

		r := NewWithStrategy(5, NewFixedDelay(time.Millisecond))
		r.SetErrorClassifier(classifier)
		err := r.Do(context.Background(), func() error {
			calls++
			if calls < 2 {
				return errors.New("retry")
			}
			return errors.New("stop")
		})

		require.Error(t, err)
		assert.Equal(t, "stop", err.Error())
		assert.Equal(t, 2, calls)
	})
}

func TestDoContext(t *testing.T) {
	t.Run("respects cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		calls := 0
		r := NewFixed(5, 100*time.Millisecond)

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := r.Do(ctx, func() error {
			calls++
			return errors.New("failed")
		})

		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, calls)
	})

	t.Run("timeout before first attempt", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()

		time.Sleep(5 * time.Millisecond) // ensure timeout
		calls := 0
		r := NewFixed(5, time.Millisecond)
		err := r.Do(ctx, func() error {
			calls++
			return errors.New("failed")
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, 0, calls)
	})
}

func TestDoWithErrAny(t *testing.T) {
	t.Run("stops on any error", func(t *testing.T) {
		calls := 0
		r := NewFixed(5, time.Millisecond)
		err := r.Do(context.Background(), func() error {
			calls++
			return errors.New("some error")
		}, ErrAny)
		require.Error(t, err)
		assert.Equal(t, 1, calls, "should stop on first error with ErrAny")
	})

	t.Run("combines with other critical errors", func(t *testing.T) {
		counts := make(map[string]int)
		r := NewFixed(5, time.Millisecond)
		criticalErr := errors.New("critical")

		err := r.Do(context.Background(), func() error {
			// return different errors
			counts["total"]++
			if counts["total"] == 2 {
				return criticalErr
			}
			return errors.New("non-critical")
		}, criticalErr, ErrAny)

		require.Error(t, err)
		assert.Equal(t, 1, counts["total"], "should stop on first error when ErrAny is used")
	})
}

func TestNewBackoff(t *testing.T) {
	r := NewBackoff(5, time.Second)
	assert.Equal(t, 5, r.attempts)

	st, ok := r.strategy.(*backoff)
	require.True(t, ok)

	// check defaults
	assert.Equal(t, time.Second, st.initial)
	assert.Equal(t, 30*time.Second, st.maxDelay)
	assert.Equal(t, BackoffExponential, st.btype)
	assert.InDelta(t, 0.1, st.jitter, 0.0001, "default jitter")

	// check with options
	r = NewBackoff(5, time.Second,
		WithMaxDelay(5*time.Second),
		WithBackoffType(BackoffLinear),
		WithJitter(0.2),
	)
	st, ok = r.strategy.(*backoff)
	require.True(t, ok)
	assert.Equal(t, time.Second, st.initial)
	assert.Equal(t, 5*time.Second, st.maxDelay)
	assert.Equal(t, BackoffLinear, st.btype)
	assert.InDelta(t, 0.2, st.jitter, 0.0001, "custom jitter")
}

func TestBackoffReal(t *testing.T) {
	startTime := time.Now()
	var attempts []time.Time

	expectedAttempts := 4
	r := NewBackoff(expectedAttempts, 10*time.Millisecond, WithJitter(0))

	// record all attempt times
	err := r.Do(context.Background(), func() error {
		attempts = append(attempts, time.Now())
		return errors.New("test error")
	})
	require.Error(t, err)

	assert.Len(t, attempts, expectedAttempts, "should make exactly %d attempts", expectedAttempts)

	// first attempt should be immediate
	assert.Less(t, attempts[0].Sub(startTime), 5*time.Millisecond)

	// check intervals between attempts
	var intervals []time.Duration
	for i := 1; i < len(attempts); i++ {
		intervals = append(intervals, attempts[i].Sub(attempts[i-1]))
		t.Logf("attempt %d interval: %v", i, intervals[i-1])
	}

	// check total time for all attempts
	// with exponential backoff and 10ms initial delay we expect:
	// - attempt 1 - immediate (0ms)
	// - attempt 2 - after 10ms delay  (total ~10ms)
	// - attempt 3 - after 20ms delay  (total ~30ms)
	// - attempt 4 - after 40ms delay  (total ~70ms)
	totalTime := attempts[len(attempts)-1].Sub(startTime)
	assert.Greater(t, totalTime, 65*time.Millisecond)
	assert.Less(t, totalTime, 75*time.Millisecond)
}

func ExampleRepeater_Do() {
	// create repeater with exponential backoff
	r := NewBackoff(5, time.Second)

	err := r.Do(context.Background(), func() error {
		// simulating successful operation
		return nil
	})

	fmt.Printf("completed with error: %v", err)
	// Output: completed with error: <nil>
}

func ExampleNewFixed() {
	// create repeater with fixed 100ms delay between attempts
	r := NewFixed(3, 100*time.Millisecond)

	// retry on "temp error" but give up immediately on "critical error"
	criticalErr := errors.New("critical error")

	// run Do and check the returned error
	err := r.Do(context.Background(), func() error {
		// simulating critical error
		return criticalErr
	}, criticalErr)

	if err != nil {
		fmt.Printf("got expected error: %v", err)
	}
	// Output: got expected error: critical error
}

func ExampleNewBackoff() {
	// create backoff repeater with custom settings
	r := NewBackoff(3, time.Millisecond,
		WithMaxDelay(10*time.Millisecond),
		WithBackoffType(BackoffLinear),
		WithJitter(0),
	)

	var attempts int
	err := r.Do(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary error")
		}
		return nil
	})

	fmt.Printf("completed with error: %v after %d attempts", err, attempts)
	// Output: completed with error: <nil> after 3 attempts
}

func TestStats(t *testing.T) {
	t.Run("success on first attempt", func(t *testing.T) {
		r := NewFixed(3, 10*time.Millisecond)
		start := time.Now()

		err := r.Do(context.Background(), func() error {
			time.Sleep(5 * time.Millisecond)
			return nil
		})

		require.NoError(t, err)
		stats := r.Stats()

		assert.Equal(t, 1, stats.Attempts)
		assert.True(t, stats.Success)
		require.NoError(t, stats.LastError)
		assert.GreaterOrEqual(t, stats.WorkDuration, 5*time.Millisecond)
		assert.Equal(t, time.Duration(0), stats.DelayDuration)
		assert.GreaterOrEqual(t, stats.TotalDuration, 5*time.Millisecond)
		assert.WithinDuration(t, start, stats.StartedAt, time.Millisecond)
		assert.False(t, stats.FinishedAt.IsZero())
	})

	t.Run("success after retries", func(t *testing.T) {
		r := NewFixed(5, 10*time.Millisecond)
		attempts := 0

		err := r.Do(context.Background(), func() error {
			attempts++
			time.Sleep(5 * time.Millisecond)
			if attempts < 3 {
				return errors.New("not yet")
			}
			return nil
		})

		require.NoError(t, err)
		stats := r.Stats()

		assert.Equal(t, 3, stats.Attempts)
		assert.True(t, stats.Success)
		require.NoError(t, stats.LastError)
		assert.GreaterOrEqual(t, stats.WorkDuration, 15*time.Millisecond)  // 3 attempts * 5ms each
		assert.GreaterOrEqual(t, stats.DelayDuration, 20*time.Millisecond) // 2 delays * 10ms each
		assert.GreaterOrEqual(t, stats.TotalDuration, 35*time.Millisecond)
	})

	t.Run("failure after all attempts", func(t *testing.T) {
		r := NewFixed(3, 5*time.Millisecond)
		expectedErr := errors.New("always fails")

		err := r.Do(context.Background(), func() error {
			time.Sleep(2 * time.Millisecond)
			return expectedErr
		})

		require.Error(t, err)
		stats := r.Stats()

		assert.Equal(t, 3, stats.Attempts)
		assert.False(t, stats.Success)
		assert.Equal(t, expectedErr, stats.LastError)
		assert.GreaterOrEqual(t, stats.WorkDuration, 6*time.Millisecond)   // 3 attempts * 2ms each
		assert.GreaterOrEqual(t, stats.DelayDuration, 10*time.Millisecond) // 2 delays * 5ms each
		assert.GreaterOrEqual(t, stats.TotalDuration, 16*time.Millisecond)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		r := NewFixed(5, 20*time.Millisecond)

		go func() {
			time.Sleep(25 * time.Millisecond)
			cancel()
		}()

		err := r.Do(ctx, func() error {
			time.Sleep(10 * time.Millisecond)
			return errors.New("failed")
		})

		require.ErrorIs(t, err, context.Canceled)
		stats := r.Stats()

		assert.GreaterOrEqual(t, stats.Attempts, 1) // at least one attempt before cancellation
		assert.LessOrEqual(t, stats.Attempts, 2)    // but no more than 2
		assert.False(t, stats.Success)
		require.ErrorIs(t, stats.LastError, context.Canceled)
		assert.GreaterOrEqual(t, stats.WorkDuration, 10*time.Millisecond) // at least 1 attempt * 10ms
		// delay duration depends on when cancellation happens
	})

	t.Run("critical error stops immediately", func(t *testing.T) {
		criticalErr := errors.New("critical")
		r := NewFixed(5, 10*time.Millisecond)

		err := r.Do(context.Background(), func() error {
			time.Sleep(3 * time.Millisecond)
			return criticalErr
		}, criticalErr)

		require.ErrorIs(t, err, criticalErr)
		stats := r.Stats()

		assert.Equal(t, 1, stats.Attempts)
		assert.False(t, stats.Success)
		assert.Equal(t, criticalErr, stats.LastError)
		assert.GreaterOrEqual(t, stats.WorkDuration, 3*time.Millisecond)
		assert.Equal(t, time.Duration(0), stats.DelayDuration) // no delays for critical error
	})

	t.Run("multiple calls reset stats", func(t *testing.T) {
		r := NewFixed(2, 5*time.Millisecond)

		// first call - failure
		err := r.Do(context.Background(), func() error {
			return errors.New("always fails")
		})
		require.Error(t, err)

		stats1 := r.Stats()
		assert.Equal(t, 2, stats1.Attempts)
		assert.False(t, stats1.Success)

		// second call - success
		err = r.Do(context.Background(), func() error {
			return nil
		})
		require.NoError(t, err)

		stats2 := r.Stats()
		assert.Equal(t, 1, stats2.Attempts)
		assert.True(t, stats2.Success)
		require.NoError(t, stats2.LastError)

		// stats should be different
		assert.NotEqual(t, stats1.StartedAt, stats2.StartedAt)
		assert.NotEqual(t, stats1.FinishedAt, stats2.FinishedAt)
	})

	t.Run("backoff strategy stats", func(t *testing.T) {
		r := NewBackoff(3, 10*time.Millisecond, WithJitter(0))
		attempts := 0

		err := r.Do(context.Background(), func() error {
			attempts++
			time.Sleep(5 * time.Millisecond)
			return errors.New("fail")
		})

		require.Error(t, err)
		stats := r.Stats()

		assert.Equal(t, 3, stats.Attempts)
		assert.False(t, stats.Success)
		assert.GreaterOrEqual(t, stats.WorkDuration, 15*time.Millisecond) // 3 attempts * 5ms each
		// with exponential backoff: 10ms + 20ms = 30ms
		assert.GreaterOrEqual(t, stats.DelayDuration, 30*time.Millisecond)
		assert.Less(t, stats.DelayDuration, 35*time.Millisecond)
	})
}
