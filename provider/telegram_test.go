package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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

	// Get token
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

	// Make sure we get error without first confirming auth request
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"request is not verified yet"}`+"\n", w.Body.String())

	time.Sleep(tgAuthRequestLifetime)

	// Confirm auth request expired
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"request expired"}`+"\n", w.Body.String())
}

func TestTelegramConfirmedRequest(t *testing.T) {
	var servedToken string
	var mu sync.Mutex

	m := &TelegramAPIMock{
		GetUpdatesFunc: func(ctx context.Context) (*telegramUpdate, error) {
			var upd telegramUpdate

			mu.Lock()
			defer mu.Unlock()
			if servedToken != "" {
				resp := fmt.Sprintf(getUpdatesResp, servedToken)

				err := json.Unmarshal([]byte(resp), &upd)
				if err != nil {
					t.Fatal(err)
				}
			}
			return &upd, nil
		},
		AvatarFunc: func(ctx context.Context, userID int) (string, error) {
			assert.Equal(t, 313131313, userID)
			return "http://t.me/avatar.png", nil
		},
		SendFunc: func(ctx context.Context, id int, text string) error {
			assert.Equal(t, 313131313, id)
			assert.Equal(t, "success", text)
			return nil
		},
		BotInfoFunc: botInfoFunc,
	}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// Get token
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

	mu.Lock()
	servedToken = resp.Token
	mu.Unlock()

	// Check the token confirmation
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

	// Test request has been invalidated
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", resp.Token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "request should get revoked")
	assert.Equal(t, `{"error":"request is not found"}`+"\n", w.Body.String())
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

	// Same TestVerifyHandler_Logout
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
			assert.Equal(t, 313131313, id)
			return nil
		},
		AvatarFunc: func(ctx context.Context, userID int) (string, error) {
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

	// Verify that get token will return bot name
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
	defer cancel()
	go tg.Run(ctx)
	assert.Eventually(t, func() bool {
		return tg.ProcessUpdate(ctx, "").Error() == "Run goroutine should not be used with ProcessUpdate"
	}, time.Millisecond*100, time.Millisecond*10, "ProcessUpdate should not work same time as Run")
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
