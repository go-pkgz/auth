package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	authtoken "github.com/go-pkgz/auth/token"
)

// same across all tests
var botInfoFunc = func(ctx context.Context) (*botInfo, error) {
	return &botInfo{Username: "my_auth_bot"}, nil
}

func TestTgLoginHandlerErrors(t *testing.T) {
	tg := TelegramHandler{Telegram: NewTelegramAPI("test", http.DefaultClient)}

	r := httptest.NewRequest("GET", "/login?site=remark", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "request should fail")

	var resp = struct {
		Error string `json:"error"`
	}{}

	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "failed to process login request", resp.Error)
}

func TestTelegramUnconfirmedRequest(t *testing.T) {
	m := &TelegramAPIMock{
		GetUpdatesFunc: func(ctx context.Context) (*telegramUpdate, error) {
			return &telegramUpdate{}, nil
		},
		BotInfoFunc: botInfoFunc,
	}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "request should succeed")

	var resp = struct {
		Token string `json:"token"`
		Bot   string `json:"bot"`
	}{}

	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	assert.Equal(t, "my_auth_bot", resp.Bot)
	token := resp.Token

	// make sure we get error without first confirming auth request
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"request is not verified yet"}`+"\n", w.Body.String())

	time.Sleep(tgAuthRequestLifetime)

	// confirm auth request expired
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"request expired"}`+"\n", w.Body.String())
}

func TestTelegramConfirmedRequest(t *testing.T) {
	var servedToken string
	// is set when token becomes used,
	// no sync is required because only a single goroutine in TelegramHandler.Run() reads and writes it
	var tokenAlreadyUsed bool

	var wgToken sync.WaitGroup
	wgToken.Add(1)
	defer func() {
		if t.Failed() && servedToken == "" {
			wgToken.Done() // for the case when test fails before token is generated
		}
	}()

	m := &TelegramAPIMock{
		GetUpdatesFunc: func(ctx context.Context) (*telegramUpdate, error) {
			wgToken.Wait()

			if tokenAlreadyUsed || t.Failed() {
				return nil, fmt.Errorf("token %s has been already used", servedToken)
			}

			var upd telegramUpdate
			resp := fmt.Sprintf(getUpdatesResp, servedToken)
			err := json.Unmarshal([]byte(resp), &upd)
			if err != nil {
				t.Fatal(err)
			}

			// token is served only once
			tokenAlreadyUsed = true

			return &upd, nil
		},
		SendFunc: func(ctx context.Context, id int, text string) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			assert.Equal(t, 313131313, id)
			assert.Equal(t, "success", text)
			return nil
		},
		BotInfoFunc: botInfoFunc,
	}

	// stand up a tiny server that serves the avatar bytes — the
	// saveTelegramAvatar helper does an HTTP GET on whatever URL Avatar
	// returns; using a real, reachable URL keeps the bot-token redaction
	// logic exercised end-to-end.
	avatarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("png-bytes"))
	}))
	defer avatarSrv.Close()
	m.AvatarFunc = func(ctx context.Context, userID int) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		assert.Equal(t, 313131313, userID)
		return avatarSrv.URL + "/file/botSECRET-TOKEN/photo.jpg", nil
	}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "request should succeed")

	var resp = struct {
		Token string `json:"token"`
		Bot   string `json:"bot"`
	}{}

	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "my_auth_bot", resp.Bot)
	assert.NotEmpty(t, resp.Token)

	servedToken = resp.Token
	wgToken.Done()

	// check the token confirmation
	assert.Eventually(t, func() bool {
		r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", resp.Token), nil)
		w = httptest.NewRecorder()
		tg.LoginHandler(w, r)
		return w.Code == http.StatusOK
	}, apiPollInterval*10, apiPollInterval, "response code should be 200")

	info := struct {
		Name    string `name:"name"`
		ID      string `id:"id"`
		Picture string `json:"picture"`
	}{}
	err = json.NewDecoder(w.Body).Decode(&info)
	assert.NoError(t, err)

	assert.Equal(t, "Joe", info.Name)
	assert.Contains(t, info.ID, "telegram_")
	assert.Equal(t, "http://example.com/ava12345.png", info.Picture)

	// test request has been invalidated
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", resp.Token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "request should get revoked")
	assert.Equal(t, `{"error":"request is not found"}`+"\n", w.Body.String())
}

func TestRedactBotURLInErr(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want string
	}{
		{name: "nil error", in: nil, want: ""},
		{name: "error without bot pattern is unchanged", in: fmt.Errorf("plain error"), want: "plain error"},
		{name: "bot token in URL is redacted", in: fmt.Errorf(`Get "https://api.telegram.org/file/bot1234567:SECRET-TOK_EN-x/photo.jpg": dial tcp`),
			want: `Get "https://api.telegram.org/file/bot<redacted>/photo.jpg": dial tcp`},
		{name: "wrapped error with bot pattern is redacted",
			in:   fmt.Errorf("wrap: %w", fmt.Errorf(`Get "https://api.telegram.org/bot1234:abc-def_99/getMe": context deadline`)),
			want: `wrap: Get "https://api.telegram.org/bot<redacted>/getMe": context deadline`},
		{name: "non-path bot identifiers (botFather, botanic) are not over-redacted",
			in:   fmt.Errorf("user @botFather mentioned in chat about botanic gardens"),
			want: `user @botFather mentioned in chat about botanic gardens`},
		{name: "bot id without trailing slash is not redacted (anchored regex requires path boundaries)",
			in:   fmt.Errorf(`reference to bot1234:abc-def_99 in narrative text`),
			want: `reference to bot1234:abc-def_99 in narrative text`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactBotURLInErr(tt.in)
			if tt.in == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.Error())
		})
	}
}

func TestSaveTelegramAvatar_TransportErrorDoesNotLeakBotToken(t *testing.T) {
	const botToken = "1234567:SECRET-bot-token-do-not-log"
	var logBuf strings.Builder
	captureLog := logger.Func(func(format string, args ...any) {
		fmt.Fprintf(&logBuf, format, args...)
	})

	th := &TelegramHandler{
		AvatarSaver: &mockAvatarSaver{},
		L:           captureLog,
	}
	// unreachable host -- forces http.Client.Do to return a *url.Error whose
	// default stringification embeds the full URL (including bot token).
	got := th.saveTelegramAvatar(context.Background(), "user1",
		"https://api.telegram.invalid/file/bot"+botToken+"/photo.jpg")
	assert.Equal(t, "", got)
	assert.NotContains(t, logBuf.String(), botToken,
		"bot token must not appear in log even when http.Client.Do returns an error containing the URL")
}

func TestSaveTelegramAvatar_BotTokenNeverLogged(t *testing.T) {
	const botToken = "1234567:SECRET-bot-token-do-not-log"
	var logBuf strings.Builder
	captureLog := logger.Func(func(format string, args ...any) {
		fmt.Fprintf(&logBuf, format, args...)
	})

	avatarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("png"))
	}))
	defer avatarSrv.Close()

	t.Run("returns proxy URL via PutContent and does not leak bot token", func(t *testing.T) {
		logBuf.Reset()
		th := &TelegramHandler{
			AvatarSaver: &mockAvatarSaver{},
			L:           captureLog,
		}
		got := th.saveTelegramAvatar(context.Background(), "user1",
			avatarSrv.URL+"/file/bot"+botToken+"/photo.jpg")
		assert.Equal(t, "http://example.com/ava12345.png", got)
		assert.NotContains(t, logBuf.String(), botToken, "bot token must never appear in logs")
	})

	t.Run("returns empty when saver lacks PutContent and warns operator", func(t *testing.T) {
		logBuf.Reset()
		th := &TelegramHandler{
			AvatarSaver: legacyAvatarSaver{},
			L:           captureLog,
		}
		got := th.saveTelegramAvatar(context.Background(), "user1",
			avatarSrv.URL+"/file/bot"+botToken+"/photo.jpg")
		assert.Equal(t, "", got, "Picture must be empty rather than carry bot URL")
		assert.NotContains(t, logBuf.String(), botToken, "bot token must never appear in logs")
		assert.Contains(t, logBuf.String(), "telegram avatar dropped")
	})

	t.Run("empty avatar URL returns empty without fetch attempt", func(t *testing.T) {
		logBuf.Reset()
		th := &TelegramHandler{AvatarSaver: &mockAvatarSaver{}, L: captureLog}
		got := th.saveTelegramAvatar(context.Background(), "user1", "")
		assert.Equal(t, "", got)
	})

	t.Run("non-200 status from Telegram file API returns empty", func(t *testing.T) {
		logBuf.Reset()
		failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "expired file_id", http.StatusNotFound)
		}))
		defer failSrv.Close()

		th := &TelegramHandler{AvatarSaver: &mockAvatarSaver{}, L: captureLog}
		got := th.saveTelegramAvatar(context.Background(), "user1",
			failSrv.URL+"/file/bot"+botToken+"/photo.jpg")
		assert.Equal(t, "", got)
		assert.Contains(t, logBuf.String(), "telegram avatar fetch returned status 404")
		assert.NotContains(t, logBuf.String(), botToken, "bot token must never appear in logs")
	})

	t.Run("PutContent error returns empty and warns operator", func(t *testing.T) {
		logBuf.Reset()
		th := &TelegramHandler{
			AvatarSaver: &failingAvatarSaver{},
			L:           captureLog,
		}
		got := th.saveTelegramAvatar(context.Background(), "user1",
			avatarSrv.URL+"/file/bot"+botToken+"/photo.jpg")
		assert.Equal(t, "", got)
		assert.Contains(t, logBuf.String(), "telegram avatar save failed")
		assert.NotContains(t, logBuf.String(), botToken, "bot token must never appear in logs")
	})

	t.Run("oversized body is rejected and warns operator", func(t *testing.T) {
		logBuf.Reset()
		bigSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			buf := make([]byte, 64<<10)
			for i := 0; i < (maxTelegramAvatarSize/len(buf))+32; i++ {
				if _, err := w.Write(buf); err != nil {
					return
				}
			}
		}))
		defer bigSrv.Close()

		th := &TelegramHandler{AvatarSaver: &mockAvatarSaver{}, L: captureLog}
		got := th.saveTelegramAvatar(context.Background(), "user1",
			bigSrv.URL+"/file/bot"+botToken+"/photo.jpg")
		assert.Equal(t, "", got)
		assert.Contains(t, logBuf.String(), "telegram avatar dropped: body exceeds")
		assert.NotContains(t, logBuf.String(), botToken, "bot token must never appear in logs")
	})
}

// failingAvatarSaver implements both Put and PutContent but its PutContent
// returns an error -- exercises the saver-side failure branch in
// saveTelegramAvatar without going through a real avatar.Proxy.
type failingAvatarSaver struct{}

func (failingAvatarSaver) Put(authtoken.User, *http.Client) (string, error)    { return "", nil }
func (failingAvatarSaver) PutContent(string, io.Reader) (string, error)        { return "", fmt.Errorf("disk full") }

type legacyAvatarSaver struct{}

func (legacyAvatarSaver) Put(authtoken.User, *http.Client) (string, error) { return "", nil }

// TestSaveTelegramAvatar_TypedNilAvatarSaverDoesNotPanic guards against the
// case where Opts.AvatarStore is unset. auth.go skips initializing
// res.avatarProxy then, so AvatarSaver ends up as a typed-nil *avatar.Proxy
// (non-nil interface wrapping a nil pointer). The avatarContentSaver type
// assertion would still succeed because interface satisfaction is structural,
// and PutContent on a nil receiver would panic on the first p.Store deref.
// The guard returns "" with a warn log instead.
func TestSaveTelegramAvatar_TypedNilAvatarSaverDoesNotPanic(t *testing.T) {
	avatarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("png-bytes"))
	}))
	defer avatarSrv.Close()

	var nilProxy *avatar.Proxy
	th := &TelegramHandler{AvatarSaver: nilProxy, L: logger.NoOp}
	// reachable URL so that without the typed-nil guard the function would
	// proceed past the fetch into PutContent on a nil receiver and panic
	// inside avatar.Proxy at p.Store deref.
	got := th.saveTelegramAvatar(context.Background(), "user1", avatarSrv.URL+"/file/botSECRET/photo.jpg")
	assert.Equal(t, "", got, "typed-nil AvatarSaver must short-circuit before fetch + PutContent")
}

// TestTelegramLoginHandler_DoesNotOverwriteSavedAvatar guards against the
// double-pipeline regression: after saveTelegramAvatar stores the bytes and
// sets Picture to a local proxy URL, LoginHandler used to call setAvatar
// which re-fetches Picture. In split-DNS / unreachable-internal-Opts.URL
// deployments the fetch fails and Proxy.Put silently overwrites the just-
// stored Telegram avatar with an identicon at the same store path. This
// test wires a real avatar.Proxy with an unreachable Opts.URL and asserts
// the second-pass fetch does not happen (Picture survives intact).
func TestTelegramLoginHandler_DoesNotOverwriteSavedAvatar(t *testing.T) {
	dir := t.TempDir()
	store := avatar.NewLocalFS(dir)
	// unreachable URL so any Proxy.Put re-fetch would fail and trigger
	// identicon fallback at the same store path
	proxy := &avatar.Proxy{
		Store:     store,
		URL:       "http://127.0.0.1:1",
		RoutePath: "/avatar",
		L:         logger.NoOp,
	}

	avatarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("png-bytes"))
	}))
	defer avatarSrv.Close()

	const tok = "registered-token"
	th := &TelegramHandler{
		ProviderName: "telegram",
		Telegram: &TelegramAPIMock{
			AvatarFunc: func(context.Context, int) (string, error) {
				return avatarSrv.URL + "/file/botSECRET/photo.jpg", nil
			},
			SendFunc:    func(context.Context, int, string) error { return nil },
			BotInfoFunc: botInfoFunc,
		},
		AvatarSaver: proxy,
		L:           logger.NoOp,
		SuccessMsg:  "ok",
	}
	th.requests.data = map[string]tgAuthRequest{
		tok: {expires: time.Now().Add(time.Hour)},
	}

	updates := &telegramUpdate{}
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(getUpdatesResp, tok)), updates))
	th.processUpdates(context.Background(), updates)

	got := th.requests.data[tok]
	require.NotNil(t, got.user, "request must be confirmed")
	pictureFromUpdate := got.user.Picture
	require.NotEmpty(t, pictureFromUpdate, "telegram path must populate Picture via PutContent")
	require.True(t, strings.HasPrefix(pictureFromUpdate, "http://127.0.0.1:1/avatar/"),
		"Picture should point at proxy URL, got: %s", pictureFromUpdate)

	jwtSvc := authtoken.NewService(authtoken.Opts{
		SecretReader: authtoken.SecretFunc(func(string) (string, error) { return "secret", nil }),
	})
	th.TokenService = jwtSvc
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?token="+tok, http.NoBody)
	require.NoError(t, err)
	th.LoginHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), pictureFromUpdate, "Picture must round-trip unchanged from saveTelegramAvatar")
}

// TestTelegramProcessUpdates_BotTokenNeverInUserPicture is the regression-style
// property test the user asked for: drives the full update-processing flow with
// a TelegramAPI mock that hands back a URL containing a bot-token-like marker,
// then asserts (a) the marker never lands in authRequest.user.Picture and
// (b) the marker never appears in any captured log line.
//
// Reverting the saveTelegramAvatar redirection (i.e. assigning avatarURL
// directly to user.Picture) makes assertion (a) fail. Reverting the avatar
// proxy log redaction makes assertion (b) fail when the avatar pipeline
// actually fetches the URL. Either way the test will scream loudly.
func TestTelegramProcessUpdates_BotTokenNeverInUserPicture(t *testing.T) {
	const botToken = "secret-bot-token-marker"
	var logBuf strings.Builder
	var logMu sync.Mutex
	captureLog := logger.Func(func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Fprintf(&logBuf, format+"\n", args...)
	})

	avatarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("png"))
	}))
	defer avatarSrv.Close()

	m := &TelegramAPIMock{
		AvatarFunc: func(context.Context, int) (string, error) {
			return avatarSrv.URL + "/file/bot" + botToken + "/photo.jpg", nil
		},
		SendFunc:    func(context.Context, int, string) error { return nil },
		BotInfoFunc: botInfoFunc,
	}

	const tok = "registered-token"
	th := &TelegramHandler{
		ProviderName: "telegram",
		Telegram:     m,
		AvatarSaver:  &mockAvatarSaver{},
		L:            captureLog,
		SuccessMsg:   "ok",
	}
	th.requests.data = map[string]tgAuthRequest{
		tok: {expires: time.Now().Add(time.Hour)},
	}

	updates := &telegramUpdate{}
	err := json.Unmarshal(fmt.Appendf(nil, getUpdatesResp, tok), updates)
	require.NoError(t, err)

	th.processUpdates(context.Background(), updates)

	got := th.requests.data[tok]
	require.NotNil(t, got.user, "auth request should have been confirmed")
	assert.NotContains(t, got.user.Picture, botToken, "User.Picture must not carry the bot token")

	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	assert.NotContains(t, logged, botToken, "no log line must contain the bot token")
}

func TestTelegramLogout(t *testing.T) {
	m := &TelegramAPIMock{
		GetUpdatesFunc: func(ctx context.Context) (*telegramUpdate, error) {
			return &telegramUpdate{}, nil
		},
		BotInfoFunc: botInfoFunc,
	}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// same TestVerifyHandler_Logout
	handler := http.HandlerFunc(tg.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", http.NoBody)
	assert.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 2, len(rr.Header()["Set-Cookie"]))

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	assert.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)

	c, err = request.Cookie("XSRF-TOKEN")
	assert.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)
}

func TestTelegramHandler_Name(t *testing.T) {
	tg := &TelegramHandler{ProviderName: "test telegram"}
	assert.Equal(t, "test telegram", tg.Name())
	assert.Equal(t, "test telegram", tg.String())
}

func TestTelegram_ProcessUpdateFlow(t *testing.T) {
	m := &TelegramAPIMock{
		GetUpdatesFunc: func(ctx context.Context) (*telegramUpdate, error) {
			return &telegramUpdate{}, nil
		},
		SendFunc: func(ctx context.Context, id int, text string) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			assert.Equal(t, 313131313, id)
			return nil
		},
		AvatarFunc: func(ctx context.Context, userID int) (string, error) {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			default:
			}
			assert.Equal(t, 313131313, userID)
			return "http://t.me/avatar.png", nil
		},
		BotInfoFunc: botInfoFunc,
	}

	tg := &TelegramHandler{
		ProviderName: "telegram",
		ErrorMsg:     "error",
		SuccessMsg:   "success",

		L: t,
		TokenService: authtoken.NewService(authtoken.Opts{
			SecretReader:   authtoken.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		AvatarSaver: &mockAvatarSaver{},
		Telegram:    m,
	}
	// we can't call addToken unless requests.data initialized either in Run or ProcessUpdate
	assert.EqualError(t, tg.ProcessUpdate(context.Background(), ""), "failed to decode provided telegram update: unexpected end of JSON input")

	assert.NoError(t, tg.addToken("token", time.Now().Add(time.Minute)))
	assert.NoError(t, tg.addToken("expired token", time.Now().Add(-time.Minute)))
	assert.Len(t, tg.requests.data, 2)
	_, err := tg.checkToken("token")
	assert.Error(t, err)
	assert.NoError(t, tg.ProcessUpdate(context.Background(), fmt.Sprintf(getUpdatesResp, "token")))
	assert.Len(t, tg.requests.data, 1, "expired token was cleaned up")
	tgUser, err := tg.checkToken("token")
	assert.NoError(t, err)
	assert.NotNil(t, tgUser)
	assert.Equal(t, "Joe", tgUser.Name)
	assert.Len(t, tg.requests.data, 1)

	assert.NoError(t, tg.addToken("expired token", time.Now().Add(-time.Minute)))
	assert.Len(t, tg.requests.data, 2)
	assert.EqualError(t, tg.ProcessUpdate(context.Background(), ""), "failed to decode provided telegram update: unexpected end of JSON input")
	assert.Len(t, tg.requests.data, 1, "expired token should be cleaned up despite the error")

	// verify that get token will return bot name
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "request should succeed")

	var resp = struct {
		Token string `json:"token"`
		Bot   string `json:"bot"`
	}{}

	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "my_auth_bot", resp.Bot)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		_ = tg.Run(ctx)
		close(runDone)
	}()
	assert.Eventually(t, func() bool {
		return tg.ProcessUpdate(ctx, "").Error() == "Run goroutine should not be used with ProcessUpdate"
	}, time.Millisecond*100, time.Millisecond*10, "ProcessUpdate should not work same time as Run")
	cancel()
	<-runDone
}

func TestTelegram_TokenVerification(t *testing.T) {
	m := &TelegramAPIMock{
		GetUpdatesFunc: func(ctx context.Context) (*telegramUpdate, error) {
			return &telegramUpdate{}, nil
		},
		BotInfoFunc: botInfoFunc,
	}

	tg, cleanup := setupHandler(t, m)
	cleanup() // we don't need tg.Run goroutine
	assert.NotNil(t, tg)
	tg.requests.data = make(map[string]tgAuthRequest) // usually done in Run()
	err := tg.addToken("token", time.Now().Add(time.Minute))
	assert.NoError(t, err)
	assert.Len(t, tg.requests.data, 1)

	// wrong token
	tgID, err := tg.checkToken("unknown token")
	assert.Empty(t, tgID)
	assert.EqualError(t, err, "request is not found")

	// right token, not verified yet
	tgID, err = tg.checkToken("token")
	assert.Empty(t, tgID)
	assert.EqualError(t, err, "request is not verified yet")

	// confirm request
	authRequest, ok := tg.requests.data["token"]
	assert.True(t, ok)
	authRequest.confirmed = true
	authRequest.user = &authtoken.User{
		Name: "telegram user name",
	}
	tg.requests.data["token"] = authRequest

	// successful check
	tgID, err = tg.checkToken("token")
	assert.NoError(t, err)
	assert.Equal(t, &authtoken.User{Name: "telegram user name"}, tgID)

	// expired token
	err = tg.addToken("expired token", time.Now().Add(-time.Minute))
	assert.NoError(t, err)
	tgID, err = tg.checkToken("expired token")
	assert.Empty(t, tgID)
	assert.EqualError(t, err, "request expired")
	assert.Len(t, tg.requests.data, 1)

	// expired token, cleaned up by the cleanup
	apiPollInterval = time.Hour
	expiredCleanupInterval = time.Millisecond * 10
	ctx, cancel := context.WithCancel(context.Background())
	go tg.Run(ctx)
	// that sleep is needed because Run() will create new requests.data map, and we need to be sure that
	// it's created by the time addToken is called.
	time.Sleep(expiredCleanupInterval)
	err = tg.addToken("expired token", time.Now().Add(-time.Minute))
	assert.NoError(t, err)
	tg.requests.RLock()
	assert.Len(t, tg.requests.data, 1)
	tg.requests.RUnlock()
	time.Sleep(expiredCleanupInterval * 2)
	tg.requests.RLock()
	assert.Len(t, tg.requests.data, 0)
	tg.requests.RUnlock()
	cancel()
	// give enough time for Run() to finish
	time.Sleep(expiredCleanupInterval)
}

func setupHandler(t *testing.T, m TelegramAPI) (tg *TelegramHandler, cleanup func()) {
	apiPollInterval = time.Millisecond * 10
	tgAuthRequestLifetime = time.Millisecond * 100

	tg = &TelegramHandler{
		ProviderName: "telegram",
		ErrorMsg:     "error",
		SuccessMsg:   "success",

		L: t,
		TokenService: authtoken.NewService(authtoken.Opts{
			SecretReader:   authtoken.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		AvatarSaver: &mockAvatarSaver{},
		Telegram:    m,
	}

	assert.Equal(t, "telegram", tg.Name())

	ctx, cleanup := context.WithCancel(context.Background())
	go func() {
		err := tg.Run(ctx)
		if err != context.Canceled {
			t.Errorf("Unexpected error: %v", err)
		}
	}()
	time.Sleep(20 * time.Millisecond)

	return tg, cleanup
}

const getUpdatesResp = `{
   "ok": true,
   "result": [
      {
         "update_id": 1000,
         "message": {
            "message_id": 4,
            "from": {
               "id": 313131313,
               "is_bot": false,
               "first_name": "Joe",
               "username": "joe123",
               "language_code": "en"
            },
            "chat": {
               "id": 313131313,
               "first_name": "Joe",
               "username": "joe123",
               "type": "private"
            },
            "date": 1601665548,
            "text": "/start %s",
            "entities": [
               {
                  "offset": 0,
                  "length": 6,
                  "type": "bot_command"
               }
            ]
         }
      }
   ]
}`

func TestTgAPI_GetUpdates(t *testing.T) {
	first := true
	tg, cleanup := prepareTgAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if first {
			assert.Equal(t, "", r.URL.Query().Get("offset"))
			first = false
		} else {
			assert.Equal(t, "1001", r.URL.Query().Get("offset"))
		}
		_, _ = fmt.Fprintf(w, getUpdatesResp, "token")
	})
	defer cleanup()

	// send request with no offset
	upd, err := tg.GetUpdates(context.Background())
	assert.NoError(t, err)

	assert.Len(t, upd.Result, 1)

	assert.Equal(t, 1001, tg.updateOffset)
	assert.Equal(t, "/start token", upd.Result[len(upd.Result)-1].Message.Text)

	// send request with offset
	_, err = tg.GetUpdates(context.Background())
	assert.NoError(t, err)
}

const sendMessageResp = `{
   "ok": true,
   "result": {
      "message_id": 100,
      "from": {
         "id": 666666666,
         "is_bot": true,
         "first_name": "Test auth bot",
         "username": "TestAuthBot"
      },
      "chat": {
         "id": 313131313,
         "first_name": "Joe",
         "username": "joe123",
         "type": "private"
      },
      "date": 1602430546,
      "text": "123"
   }
}`

func TestTgAPI_Send(t *testing.T) {
	tg, cleanup := prepareTgAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "123", r.URL.Query().Get("chat_id"))
		assert.Equal(t, "hello there", r.URL.Query().Get("text"))
		_, _ = w.Write([]byte(sendMessageResp))
	}))
	defer cleanup()

	err := tg.Send(context.Background(), 123, "hello there")
	assert.NoError(t, err)
}

const profilePhotosResp = `{
   "ok": true,
   "result": {
      "total_count": 1,
      "photos": [
         [
            {
               "file_id": "1",
               "file_unique_id": "A",
               "file_size": 8900,
               "width": 200,
               "height": 200
            }
         ]
      ]
   }
}`

const getFileResp = `{
   "ok": true,
   "result": {
      "file_id": "1",
      "file_unique_id": "A",
      "file_size": 8900,
      "file_path": "photos/file_0.jpg"
   }
}`

func TestTgAPI_Avatar(t *testing.T) {
	tg, cleanup := prepareTgAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "getUserProfilePhotos") {
			assert.Equal(t, "123", r.URL.Query().Get("user_id"))
			_, _ = w.Write([]byte(profilePhotosResp))
			return
		}

		assert.Equal(t, "1", r.URL.Query().Get("file_id"))
		_, _ = w.Write([]byte(getFileResp))

	}))
	defer cleanup()

	avatarURL, err := tg.Avatar(context.Background(), 123)
	assert.NoError(t, err)

	expected := fmt.Sprintf("https://api.telegram.org/file/bot%s/photos/file_0.jpg", tg.token)
	assert.Equal(t, expected, avatarURL)
}

const errorResp = `{"ok":false,"error_code":400,"description":"Very bad request"}`

func TestTgAPI_Error(t *testing.T) {
	tg, cleanup := prepareTgAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errorResp))
	}))
	defer cleanup()

	_, err := tg.GetUpdates(context.Background())
	assert.EqualError(t, err, "failed to fetch updates: unexpected telegram API status code 400, error: \"Very bad request\"")
}

// mockRoundTripper redirects all incoming requests to mock url
type mockRoundTripper struct{ url string }

func (m mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	u, _ := url.Parse(m.url)
	r.URL.Host = u.Host
	r.URL.Scheme = u.Scheme
	return http.DefaultClient.Do(r)
}

const getMeResp = `{
   "ok": true,
   "result": {
      "id": 123456789,
      "is_bot": true,
      "first_name": "Test auth bot",
      "username": "RemarkAuthBot",
      "can_join_groups": true,
      "can_read_all_group_messages": false,
      "supports_inline_queries": false
   }
}
`

func prepareTgAPI(t *testing.T, h http.HandlerFunc) (tg *tgAPI, cleanup func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.String(), "xxxsupersecretxxx")

		if strings.Contains(r.URL.String(), "getMe") {
			_, _ = w.Write([]byte(getMeResp))
			return
		}

		h(w, r)
	}))

	client := &http.Client{
		Transport: mockRoundTripper{srv.URL},
	}

	return NewTelegramAPI("xxxsupersecretxxx", client).(*tgAPI), srv.Close
}
