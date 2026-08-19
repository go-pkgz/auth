package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimeout(t *testing.T) {
	t.Run("fast handler passes through status, headers and body", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Custom", "value")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("ok"))
		})

		rec := httptest.NewRecorder()
		Timeout(time.Second)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
		assert.Equal(t, "value", rec.Header().Get("X-Custom"))
	})

	t.Run("handler without explicit status defaults to 200", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("body"))
		})

		rec := httptest.NewRecorder()
		Timeout(time.Second)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "body", rec.Body.String())
	})

	t.Run("context carries the deadline", func(t *testing.T) {
		var hasDeadline bool
		handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, hasDeadline = r.Context().Deadline()
		})

		rec := httptest.NewRecorder()
		Timeout(time.Second)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		assert.True(t, hasDeadline, "handler should see a context deadline")
	})

	t.Run("non-positive timeout disables the middleware", func(t *testing.T) {
		for _, d := range []time.Duration{0, -time.Second} {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, hasDeadline := r.Context().Deadline()
				assert.False(t, hasDeadline, "a disabled timeout must not set a deadline")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})

			rec := httptest.NewRecorder()
			Timeout(d)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "ok", rec.Body.String())
		}
	})

	t.Run("handler ignoring the context is timed out at the deadline", func(t *testing.T) {
		release := make(chan struct{})
		handlerDone := make(chan struct{})
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defer close(handlerDone)
			<-release // ignores the request context entirely
			_, _ = w.Write([]byte("late"))
		})

		rec := httptest.NewRecorder()
		start := time.Now()
		Timeout(20*time.Millisecond)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		elapsed := time.Since(start)

		assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
		assert.Empty(t, rec.Body.String(), "the handler's buffered output must be discarded")
		assert.Less(t, elapsed, 2*time.Second, "ServeHTTP must return at the deadline, not wait for the handler")

		close(release)
		<-handlerDone
	})

	t.Run("handler respecting the context times out", func(t *testing.T) {
		handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})

		rec := httptest.NewRecorder()
		Timeout(20*time.Millisecond)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
	})

	t.Run("partially written response is discarded on timeout", func(t *testing.T) {
		release := make(chan struct{})
		handlerDone := make(chan struct{})
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defer close(handlerDone)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial"))
			<-release
		})

		rec := httptest.NewRecorder()
		Timeout(20*time.Millisecond)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))

		assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
		assert.Empty(t, rec.Body.String(), "buffered partial output must not leak after a timeout")

		close(release)
		<-handlerDone
	})

	t.Run("writes after the timeout return ErrHandlerTimeout", func(t *testing.T) {
		release := make(chan struct{})
		handlerDone := make(chan struct{})
		var writeErr error
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defer close(handlerDone)
			<-release // resumes only after the timeout has fired
			_, writeErr = w.Write([]byte("late"))
		})

		rec := httptest.NewRecorder()
		Timeout(20*time.Millisecond)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		assert.Equal(t, http.StatusGatewayTimeout, rec.Code)

		close(release)
		<-handlerDone
		assert.ErrorIs(t, writeErr, http.ErrHandlerTimeout)
	})

	t.Run("duplicate WriteHeader keeps the first status", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.WriteHeader(http.StatusBadRequest) // ignored
		})

		rec := httptest.NewRecorder()
		Timeout(time.Second)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		assert.Equal(t, http.StatusCreated, rec.Code)
	})

	t.Run("WriteHeader after the timeout is a no-op", func(t *testing.T) {
		release := make(chan struct{})
		handlerDone := make(chan struct{})
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defer close(handlerDone)
			<-release // resumes only after the timeout has fired
			w.WriteHeader(http.StatusTeapot)
		})

		rec := httptest.NewRecorder()
		Timeout(20*time.Millisecond)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		assert.Equal(t, http.StatusGatewayTimeout, rec.Code)

		close(release)
		<-handlerDone
	})

	t.Run("handler panic propagates", func(t *testing.T) {
		handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom")
		})

		rec := httptest.NewRecorder()
		assert.PanicsWithValue(t, "boom", func() {
			Timeout(time.Second)(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))
		})
	})

	t.Run("cancelled parent context stops the handler without a 504", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		handlerDone := make(chan struct{})
		handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			defer close(handlerDone)
			<-r.Context().Done()
		})

		req := httptest.NewRequest("GET", "/", http.NoBody).WithContext(ctx)
		rec := httptest.NewRecorder()
		cancel() // parent is cancelled, not timed out

		Timeout(time.Second)(handler).ServeHTTP(rec, req)
		<-handlerDone
		assert.NotEqual(t, http.StatusGatewayTimeout, rec.Code, "parent cancellation must not send a 504")
	})

	t.Run("writes after parent cancellation return the context error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		handlerDone := make(chan struct{})
		var writeErr error
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(handlerDone)
			<-r.Context().Done()
			// the middleware records the cancellation cause under the writer's lock; retry
			// until a write is rejected so the assertion doesn't race that bookkeeping
			for writeErr == nil {
				_, writeErr = w.Write([]byte("x"))
			}
		})

		req := httptest.NewRequest("GET", "/", http.NoBody).WithContext(ctx)
		cancel()
		Timeout(time.Second)(handler).ServeHTTP(httptest.NewRecorder(), req)
		<-handlerDone

		assert.ErrorIs(t, writeErr, context.Canceled, "a write after parent cancellation must return the context error")
		assert.NotErrorIs(t, writeErr, http.ErrHandlerTimeout, "cancellation must not be reported as a handler timeout")
	})
}
