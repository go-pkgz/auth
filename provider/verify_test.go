package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

// nolint
var (
	testConfirmedToken      = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.D8AvAunK7Tj-P6P56VyaoZ-hyA6U8duZ9HV8-ACEya8`
	testConfirmedBadIDToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJibGFoQHVzZXIuY29tIn19.hB91-kyY9-Q2Ln6IJGR9StQi-QQiXYu8SV31YhOoTbc`
	testConfirmedGravatar   = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJncmF2YTo6ZWVmcmV0c291bEBnbWFpbC5jb20ifX0.yQTtG7neX3YjLZ-SGeiiNmwNfJWA7nR50KAxDw834XE`
	testConfirmedExpired    = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTU2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.bCFMAwCg1_l4yuEzFYzd0q9PstY-auHe2rwLqltffqo`
)

func TestVerifyHandler_LoginSendConfirm(t *testing.T) {

	emailer := mockSender{}
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   SenderFunc(emailer.Send),
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user=test123&site=remark42", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "blah@user.com", emailer.to)
	assert.Contains(t, emailer.text, "test123 blah@user.com remark42 token:")

	tknStr := strings.Split(emailer.text, " token:")[1]
	tkn, err := e.TokenService.Parse(tknStr)
	assert.NoError(t, err)
	t.Logf("%s %+v", tknStr, tkn)
	assert.Equal(t, "test123::blah@user.com", tkn.Handshake.ID)
	assert.Equal(t, "remark42", tkn.Audience)
	assert.True(t, tkn.ExpiresAt > tkn.NotBefore)

	assert.Equal(t, "test", e.Name())
}

func TestVerifyHandler_LoginSendConfirmEscapesBadInput(t *testing.T) {

	emailer := mockSender{}
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   SenderFunc(emailer.Send),
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	badData := "<html><script>nasty stuff</script>&lt;escaped&gt;</html>"
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user="+url.QueryEscape(badData)+"&site="+url.QueryEscape(badData), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "blah@user.com", emailer.to)
	expectedEscaped := "&lt;html&gt;&lt;script&gt;nasty stuff&lt;/script&gt;&amp;lt;escaped&amp;gt;&lt;/html&gt;"
	assert.Contains(t, emailer.text, expectedEscaped+" blah@user.com "+expectedEscaped+" token:")

	tknStr := strings.Split(emailer.text, " token:")[1]
	tkn, err := e.TokenService.Parse(tknStr)
	assert.NoError(t, err)
	t.Logf("%s %+v", tknStr, tkn)
	// not escaped in these fields as they are not rendered as HTML
	assert.Equal(t, badData+"::blah@user.com", tkn.Handshake.ID)
	assert.Equal(t, badData, tkn.Audience)
	assert.True(t, tkn.ExpiresAt > tkn.NotBefore)

	assert.Equal(t, "test", e.Name())
}

func TestVerifyHandler_LoginAcceptConfirm(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedToken), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"test123","id":"test_63c1017838e567a526800790805eae4dc975402b","picture":""}`+"\n", rr.Body.String())

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	claims, err := e.TokenService.Parse(c.Value)
	require.NoError(t, err)
	t.Logf("%+v", claims)
	assert.Equal(t, "remark42", claims.Audience)
	assert.Equal(t, "iss-test", claims.Issuer)
	assert.True(t, claims.ExpiresAt > time.Now().Unix())
	assert.Equal(t, "test123", claims.User.Name)
	assert.Equal(t, true, claims.SessionOnly)
}

// TestVerifyHandler_PublicFromFlow_RejectsExternalHost drives the public flow:
// /login?from=... -> sendConfirmation -> email-link click -> /login?token=...
// -> validator rejects. Catches regressions where sendConfirmation drops the
// from query param (the JWT then carries an empty Handshake.From, the
// validator never fires, and production silently ignores the redirect).
func TestVerifyHandler_PublicFromFlow_RejectsExternalHost(t *testing.T) {
	emailer := &mockSender{}
	jwtSvc := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24 * 31,
	})
	e := VerifyHandler{
		ProviderName:         "test",
		TokenService:         jwtSvc,
		Issuer:               "iss-test",
		L:                    logger.Std,
		Sender:               SenderFunc(emailer.Send),
		Template:             "token:{{.Token}}",
		AllowedRedirectHosts: token.AllowedHostsFunc(func() ([]string, error) { return nil, nil }),
	}

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET",
		"/login?address=blah@user.com&user=test123&site=remark42&from=https://evil.example.com/phish",
		http.NoBody)
	require.NoError(t, err)
	http.HandlerFunc(e.LoginHandler).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	tknStr := strings.TrimPrefix(emailer.text, "token:")
	require.NotEmpty(t, tknStr, "sendConfirmation must produce a token")

	// sanity: the produced token MUST carry from in the handshake claim --
	// otherwise the validator at the redemption side has nothing to act on
	// and the redirect would silently no-op in production.
	parsed, err := jwtSvc.Parse(tknStr)
	require.NoError(t, err)
	require.NotNil(t, parsed.Handshake)
	require.Equal(t, "https://evil.example.com/phish", parsed.Handshake.From,
		"sendConfirmation must propagate ?from to handshake JWT, otherwise the redirect validator never runs in production")

	// redeem and assert the validator rejects the external host
	rr2 := httptest.NewRecorder()
	req2, err := http.NewRequest("GET", "/login?token="+tknStr, http.NoBody)
	require.NoError(t, err)
	http.HandlerFunc(e.LoginHandler).ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code, "must return user JSON, not 307 to evil")
	assert.Equal(t, "", rr2.Header().Get("Location"))
	assert.NotContains(t, rr2.Body.String(), "evil.example.com")
}

func TestVerifyHandler_LoginAcceptConfirmFromRejectsExternalHost(t *testing.T) {
	jwtSvc := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24 * 31,
	})
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: jwtSvc,
		Issuer:       "iss-test",
		L:            logger.Std,
		// non-nil empty allowlist enables the policy with no extra hosts
		AllowedRedirectHosts: token.AllowedHostsFunc(func() ([]string, error) { return nil, nil }),
	}

	confTok, err := jwtSvc.Token(token.Claims{
		Handshake: &token.Handshake{
			ID:   "test123::blah@user.com",
			From: "https://evil.example.com/phish",
		},
		StandardClaims: jwt.StandardClaims{
			Audience:  "remark42",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	})
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s", confTok), http.NoBody)
	require.NoError(t, err)
	http.HandlerFunc(e.LoginHandler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "must return user JSON, not 307 to evil")
	assert.Equal(t, "", rr.Header().Get("Location"))
	assert.Contains(t, rr.Body.String(), `"name":"test123"`)
	assert.NotContains(t, rr.Body.String(), "evil.example.com")
}

func TestVerifyHandler_LoginAcceptConfirmFromAllowsAllowlistedHost(t *testing.T) {
	jwtSvc := token.NewService(token.Opts{
		SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24 * 31,
	})
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: jwtSvc,
		Issuer:       "iss-test",
		L:            logger.Std,
		AllowedRedirectHosts: token.AllowedHostsFunc(func() ([]string, error) {
			return []string{"trusted.example.com"}, nil
		}),
	}

	confTok, err := jwtSvc.Token(token.Claims{
		Handshake: &token.Handshake{
			ID:   "test123::blah@user.com",
			From: "https://trusted.example.com/back",
		},
		StandardClaims: jwt.StandardClaims{
			Audience:  "remark42",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	})
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s", confTok), http.NoBody)
	require.NoError(t, err)
	http.HandlerFunc(e.LoginHandler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code, "must 307-redirect to trusted host")
	assert.Equal(t, "https://trusted.example.com/back", rr.Header().Get("Location"))
}

func TestInMemoryVerifStore(t *testing.T) {
	mark := func(s VerifConfirmationStore, k string, ttl time.Duration) bool {
		used, err := s.MarkUsed(k, ttl)
		require.NoError(t, err)
		return used
	}

	t.Run("first MarkUsed returns false, second returns true", func(t *testing.T) {
		s := NewInMemoryVerifStore()
		assert.False(t, mark(s, "k1", time.Hour), "first call must mark and return not-used")
		assert.True(t, mark(s, "k1", time.Hour), "second call must report already-used")
	})
	t.Run("expired entry is not considered used", func(t *testing.T) {
		s := NewInMemoryVerifStore()
		assert.False(t, mark(s, "k1", time.Nanosecond))
		time.Sleep(2 * time.Millisecond)
		assert.False(t, mark(s, "k1", time.Hour), "expired entry should be reusable")
	})
	t.Run("distinct keys are independent", func(t *testing.T) {
		s := NewInMemoryVerifStore()
		assert.False(t, mark(s, "k1", time.Hour))
		assert.False(t, mark(s, "k2", time.Hour))
		assert.True(t, mark(s, "k1", time.Hour))
		assert.True(t, mark(s, "k2", time.Hour))
	})
	t.Run("concurrent same-key redemption: exactly one succeeds", func(t *testing.T) {
		s := NewInMemoryVerifStore()
		const goroutines = 50
		var wg sync.WaitGroup
		successes := int32(0)
		errs := int32(0)
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				used, err := s.MarkUsed("hot-key", time.Hour)
				if err != nil {
					atomic.AddInt32(&errs, 1)
					return
				}
				if !used {
					atomic.AddInt32(&successes, 1)
				}
			}()
		}
		wg.Wait()
		assert.EqualValues(t, 0, errs)
		assert.EqualValues(t, 1, successes, "exactly one redemption must observe alreadyUsed=false")
	})
	t.Run("amortized sweep evicts expired entries", func(t *testing.T) {
		orig := inMemoryVerifStoreSweepEvery
		inMemoryVerifStoreSweepEvery = 4
		defer func() { inMemoryVerifStoreSweepEvery = orig }()

		s := NewInMemoryVerifStore().(*inMemoryVerifStore)
		// 3 inserts with nanosecond TTL — quickly expire, no sweep yet
		// (insertCount=3 < 4)
		for i := 0; i < 3; i++ {
			used, err := s.MarkUsed(fmt.Sprintf("expired-%d", i), time.Nanosecond)
			require.NoError(t, err)
			require.False(t, used)
		}
		time.Sleep(5 * time.Millisecond) // let them expire
		s.mu.Lock()
		require.Equal(t, 3, len(s.used), "sanity: pre-sweep map holds the 3 expired entries")
		s.mu.Unlock()

		// 4th insert hits the sweep threshold, should evict the 3 expired
		_, err := s.MarkUsed("fresh", time.Hour)
		require.NoError(t, err)

		s.mu.Lock()
		assert.Equal(t, 1, len(s.used), "sweep evicted the expired entries; only fresh remains")
		s.mu.Unlock()
	})
}

func TestScrubTokenFromRequest(t *testing.T) {
	t.Run("token query is replaced with redacted sentinel", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/login?token=secret-jwt&sess=1", http.NoBody)
		require.NoError(t, err)
		out := scrubTokenFromRequest(req)
		assert.Equal(t, "secret-jwt", req.URL.Query().Get("token"), "original request must not be mutated")
		assert.Equal(t, "<redacted>", out.URL.Query().Get("token"))
		assert.Equal(t, "1", out.URL.Query().Get("sess"), "other query params preserved")
	})
	t.Run("missing token query returns request unchanged", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/login?sess=1", http.NoBody)
		require.NoError(t, err)
		out := scrubTokenFromRequest(req)
		assert.Same(t, req, out)
	})
	t.Run("nil request returns nil", func(t *testing.T) {
		assert.Nil(t, scrubTokenFromRequest(nil))
	})
}

func TestVerifConfirmationStoreFunc(t *testing.T) {
	calls := 0
	var lastKey string
	var lastTTL time.Duration
	var s VerifConfirmationStore = VerifConfirmationStoreFunc(func(key string, ttl time.Duration) (bool, error) {
		calls++
		lastKey, lastTTL = key, ttl
		return calls > 1, nil
	})

	used, err := s.MarkUsed("k1", 5*time.Minute)
	require.NoError(t, err)
	assert.False(t, used)
	assert.Equal(t, "k1", lastKey)
	assert.Equal(t, 5*time.Minute, lastTTL)

	used, err = s.MarkUsed("k1", 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, used)
	assert.Equal(t, 2, calls)
}

func TestVerifyHandler_LoginAcceptConfirm_TypedNilStoreFuncDoesNotPanic(t *testing.T) {
	// Opts.VerifConfirmationStore can be set to a typed-nil
	// VerifConfirmationStoreFunc, which is a non-nil interface wrapping a
	// nil func. The handler must treat that as "no store configured" and
	// fall back to legacy replayable behavior, not panic.
	var nilFn VerifConfirmationStoreFunc
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:            "iss-test",
		L:                 logger.Std,
		ConfirmationStore: nilFn,
	}
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	require.NotPanics(t, func() {
		http.HandlerFunc(e.LoginHandler).ServeHTTP(rr, req)
	})
	assert.Equal(t, 200, rr.Code, "typed-nil store func must behave like no store")
}

func TestVerifyHandler_LoginAcceptConfirm_FailClosedOnStoreError(t *testing.T) {
	// MarkUsed returning a non-nil err is the security-critical fail-closed
	// branch: a backend (e.g. Redis) outage MUST reject the redemption to
	// avoid replay during the outage window.
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
		ConfirmationStore: VerifConfirmationStoreFunc(func(string, time.Duration) (bool, error) {
			return false, fmt.Errorf("redis down")
		}),
	}
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	http.HandlerFunc(e.LoginHandler).ServeHTTP(rr, req)
	assert.Equal(t, 403, rr.Code, "non-nil markErr must fail closed")
	assert.Contains(t, rr.Body.String(), "store unavailable")
}

func TestVerifyHandler_LoginAcceptConfirm_RejectsReplay(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:            "iss-test",
		L:                 logger.Std,
		ConfirmationStore: NewInMemoryVerifStore(),
	}

	handler := http.HandlerFunc(e.LoginHandler)

	// first use: success
	rr1 := httptest.NewRecorder()
	req1, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr1, req1)
	require.Equal(t, 200, rr1.Code, "first consumption must succeed")

	// second use: must be rejected
	rr2 := httptest.NewRecorder()
	req2, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, 403, rr2.Code, "replay must be rejected")
	assert.Contains(t, rr2.Body.String(), "already")
}

func TestVerifyHandler_LoginAcceptConfirmWithAvatar(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		UseGravatar:  true,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedGravatar), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"grava","id":"test_47dbf92d92954b1297cae73a864c159b4d847b9f","picture":"https://www.gravatar.com/avatar/c82739de14cf64affaf30856ca95b851"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginAcceptConfirmWithGrAvatarDisabled(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		UseGravatar:  false,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedGravatar), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"grava","id":"test_47dbf92d92954b1297cae73a864c159b4d847b9f","picture":""}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginHandlerFailed(t *testing.T) {
	emailer := mockSender{}
	d := VerifyHandler{
		ProviderName: "test",
		Sender:       &emailer,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?user=myuser&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 400, rr.Code)
	assert.Equal(t, `{"error":"can't get user and address"}`+"\n", rr.Body.String())

	d.Sender = &mockSender{err: fmt.Errorf("some err")}
	handler = d.LoginHandler
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to send confirmation"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token=bad", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedBadIDToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, `{"error":"invalid handshake token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedExpired, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	d.Template = `{{.Blah}}`
	d.Sender = &mockSender{}
	handler = d.LoginHandler
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, `{"error":"can't execute confirmation template"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginHandlerAvatarFailed(t *testing.T) {
	emailer := mockSender{}
	d := VerifyHandler{
		ProviderName: "test",
		Sender:       &emailer,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:      "iss-test",
		L:           logger.Std,
		AvatarSaver: mockAvatarSaverVerif{err: fmt.Errorf("avatar save error")},
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to save avatar to proxy"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_AuthHandler(t *testing.T) {
	d := VerifyHandler{}
	handler := http.HandlerFunc(d.AuthHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/callback", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
}

func TestVerifyHandler_Logout(t *testing.T) {
	d := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, 2, len(rr.Header()["Set-Cookie"]))

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)

	c, err = request.Cookie("XSRF-TOKEN")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)
}

type mockSender struct {
	err error

	to   string
	text string
}

func (m *mockSender) Send(to, text string) error {
	if m.err != nil {
		return m.err
	}
	m.to = to
	m.text = text
	return nil
}

type mockAvatarSaverVerif struct {
	err error
	url string
}

func (a mockAvatarSaverVerif) Put(token.User, *http.Client) (avatarURL string, err error) {
	return a.url, a.err
}
