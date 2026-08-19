package repeater

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFixedDelay(t *testing.T) {
	s := NewFixedDelay(time.Second)
	assert.Equal(t, time.Second, s.NextDelay(1))
	assert.Equal(t, time.Second, s.NextDelay(5))
	assert.Equal(t, time.Second, s.NextDelay(0))
}

func TestBackoff(t *testing.T) {
	t.Run("base cases", func(t *testing.T) {
		s := newBackoff(time.Second, WithJitter(0))
		assert.Equal(t, 0*time.Second, s.NextDelay(0))
		assert.Equal(t, 1*time.Second, s.NextDelay(1))
	})

	t.Run("backoff types", func(t *testing.T) {
		initial := 100 * time.Millisecond

		t.Run("constant", func(t *testing.T) {
			s := newBackoff(initial, WithJitter(0), WithBackoffType(BackoffConstant))
			assert.Equal(t, initial, s.NextDelay(1))
			assert.Equal(t, initial, s.NextDelay(2))
			assert.Equal(t, initial, s.NextDelay(3))
		})

		t.Run("linear", func(t *testing.T) {
			s := newBackoff(initial, WithJitter(0), WithBackoffType(BackoffLinear))
			assert.Equal(t, 1*initial, s.NextDelay(1))
			assert.Equal(t, 2*initial, s.NextDelay(2))
			assert.Equal(t, 3*initial, s.NextDelay(3))
		})

		t.Run("exponential", func(t *testing.T) {
			s := newBackoff(initial, WithJitter(0), WithBackoffType(BackoffExponential))
			assert.Equal(t, 1*initial, s.NextDelay(1))
			assert.Equal(t, 2*initial, s.NextDelay(2))
			assert.Equal(t, 4*initial, s.NextDelay(3))
			assert.Equal(t, 8*initial, s.NextDelay(4))
		})
	})

	t.Run("max delay", func(t *testing.T) {
		s := newBackoff(time.Second, WithJitter(0), WithMaxDelay(2*time.Second))
		assert.Equal(t, 1*time.Second, s.NextDelay(1))
		assert.Equal(t, 2*time.Second, s.NextDelay(2))
		assert.Equal(t, 2*time.Second, s.NextDelay(3)) // capped at max delay
	})

	t.Run("jitter", func(t *testing.T) {
		initial := time.Second
		s := newBackoff(initial, WithJitter(0.1)) // 10% jitter

		for i := 0; i < 10; i++ {
			delay := s.NextDelay(1)
			assert.GreaterOrEqual(t, delay, 950*time.Millisecond) // initial - 5% jitter
			assert.Less(t, delay, 1050*time.Millisecond)          // initial + 5% jitter
		}
	})

	t.Run("all options", func(t *testing.T) {
		s := newBackoff(time.Second,
			WithBackoffType(BackoffLinear),
			WithMaxDelay(3*time.Second),
			WithJitter(0.2),
		)

		assert.Equal(t, time.Second, s.initial)
		assert.Equal(t, 3*time.Second, s.maxDelay)
		assert.Equal(t, BackoffLinear, s.btype)
		assert.InDelta(t, 0.2, s.jitter, 0.0001, "custom jitter")
	})

	t.Run("defaults", func(t *testing.T) {
		s := newBackoff(time.Second)
		assert.Equal(t, time.Second, s.initial)
		assert.Equal(t, 30*time.Second, s.maxDelay)
		assert.Equal(t, BackoffExponential, s.btype)
		assert.InDelta(t, 0.1, s.jitter, 0.0001, "default jitter")
	})
}
