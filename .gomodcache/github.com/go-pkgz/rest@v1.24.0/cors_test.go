package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCORS_Defaults(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	CORS()(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"))
}

func TestCORS_NoOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	// no Origin header
	w := httptest.NewRecorder()

	CORS()(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called for preflight")
	})

	req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	CORS()(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type")
}

func TestCORS_PreflightWithMaxAge(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()

	CORS(CorsMaxAge(3600))(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, "3600", resp.Header.Get("Access-Control-Max-Age"))
}

func TestCORS_SpecificOrigins(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "https://allowed.com")
		w := httptest.NewRecorder()

		CORS(CorsAllowedOrigins("https://allowed.com", "https://also-allowed.com"))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "https://allowed.com", resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "https://evil.com")
		w := httptest.NewRecorder()

		CORS(CorsAllowedOrigins("https://allowed.com"))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("case insensitive", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "HTTPS://ALLOWED.COM")
		w := httptest.NewRecorder()

		CORS(CorsAllowedOrigins("https://allowed.com"))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "HTTPS://ALLOWED.COM", resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

func TestCORS_Credentials(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("with credentials reflects origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()

		CORS(
			CorsAllowedOrigins("https://app.example.com"),
			CorsAllowCredentials(true),
		)(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	})

	t.Run("credentials with wildcard origins rejected", func(t *testing.T) {
		tbl := []struct {
			name string
			opts []CorsOpt
		}{
			{"default origins", []CorsOpt{CorsAllowCredentials(true)}},
			{"explicit wildcard", []CorsOpt{CorsAllowedOrigins("*"), CorsAllowCredentials(true)}},
			{"wildcard among others", []CorsOpt{CorsAllowedOrigins("https://app.example.com", "*"), CorsAllowCredentials(true)}},
		}
		for _, tt := range tbl {
			t.Run(tt.name, func(t *testing.T) {
				assert.PanicsWithValue(t,
					`rest: CORS with credentials can't allow "*" as an origin, list the allowed origins explicitly `+
						`or opt in with CorsUnsafeAnyOriginWithCredentials`,
					func() { CORS(tt.opts...) })
			})
		}
	})

	t.Run("wildcard without credentials allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "https://any.example.com")
		w := httptest.NewRecorder()

		CORS()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"))
	})
}

func TestCORS_CustomMethods(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "PATCH")
	w := httptest.NewRecorder()

	CORS(CorsAllowedMethods("GET", "PATCH"))(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	methods := resp.Header.Get("Access-Control-Allow-Methods")
	assert.Contains(t, methods, "GET")
	assert.Contains(t, methods, "PATCH")
	assert.NotContains(t, methods, "DELETE")
}

func TestCORS_CustomHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	CORS(CorsAllowedHeaders("X-Custom-Header", "X-Another"))(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	headers := resp.Header.Get("Access-Control-Allow-Headers")
	assert.Contains(t, headers, "X-Custom-Header")
	assert.Contains(t, headers, "X-Another")
}

func TestCORS_ExposedHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	CORS(CorsExposedHeaders("X-Request-Id", "X-Total-Count"))(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	assert.Contains(t, exposed, "X-Request-Id")
	assert.Contains(t, exposed, "X-Total-Count")
}

func TestCORS_VaryHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	CORS()(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.Contains(t, resp.Header.Get("Vary"), "Origin")
}

func TestCORS_PreflightVaryHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("preflight varies on origin, method and headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()

		CORS()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		vary := resp.Header.Values("Vary")
		assert.Contains(t, vary, "Origin")
		assert.Contains(t, vary, "Access-Control-Request-Method")
		assert.Contains(t, vary, "Access-Control-Request-Headers")
	})

	t.Run("simple request does not vary on preflight headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		CORS()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		vary := resp.Header.Values("Vary")
		assert.Contains(t, vary, "Origin")
		assert.NotContains(t, vary, "Access-Control-Request-Method")
		assert.NotContains(t, vary, "Access-Control-Request-Headers")
	})

	t.Run("non-preflight OPTIONS does not vary on preflight headers", func(t *testing.T) {
		// OPTIONS without Access-Control-Request-Method is not a preflight
		req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		CORS()(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		vary := resp.Header.Values("Vary")
		assert.Contains(t, vary, "Origin")
		assert.NotContains(t, vary, "Access-Control-Request-Method")
		assert.NotContains(t, vary, "Access-Control-Request-Headers")
	})
}

func TestCORS_OptionsWithoutPreflight(t *testing.T) {
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// OPTIONS without Access-Control-Request-Method is not a preflight
	req := httptest.NewRequest("OPTIONS", "/test", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	CORS()(handler).ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	assert.True(t, handlerCalled, "handler should be called for non-preflight OPTIONS")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCORS_Integration(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	ts := httptest.NewServer(CORS(
		CorsAllowedOrigins("https://app.example.com"),
		CorsAllowCredentials(true),
		CorsMaxAge(86400),
		CorsExposedHeaders("X-Request-Id"),
	)(handler))
	defer ts.Close()

	client := &http.Client{}

	t.Run("preflight request", func(t *testing.T) {
		req, err := http.NewRequest("OPTIONS", ts.URL+"/api", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "86400", resp.Header.Get("Access-Control-Max-Age"))
	})

	t.Run("actual request", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://app.example.com")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Contains(t, resp.Header.Get("Access-Control-Expose-Headers"), "X-Request-Id")
	})
}

func TestCORS_UnsafeAnyOriginWithCredentials(t *testing.T) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	t.Run("opting in keeps the wildcard working", func(t *testing.T) {
		tbl := []struct {
			name string
			opts []CorsOpt
		}{
			{"default origins", []CorsOpt{
				CorsAllowCredentials(true), CorsUnsafeAnyOriginWithCredentials(true)}},
			{"explicit wildcard", []CorsOpt{
				CorsAllowedOrigins("*"), CorsAllowCredentials(true), CorsUnsafeAnyOriginWithCredentials(true)}},
		}
		for _, tt := range tbl {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Origin", "https://any.example.com")
				w := httptest.NewRecorder()

				require.NotPanics(t, func() { CORS(tt.opts...)(handler).ServeHTTP(w, req) })
				resp := w.Result()
				defer resp.Body.Close()

				// the origin is reflected, not "*", which is what credentials require
				assert.Equal(t, "https://any.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
			})
		}
	})

	t.Run("opting in without credentials changes nothing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.Header.Set("Origin", "https://any.example.com")
		w := httptest.NewRecorder()

		CORS(CorsUnsafeAnyOriginWithCredentials(true))(handler).ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"))
	})
}
