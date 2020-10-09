package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authtoken "github.com/go-pkgz/auth/token"
	"github.com/stretchr/testify/assert"
)

func TestTelegramUnconfirmedRequest(t *testing.T) {
	m := &tgMock{
		t:            t,
		expectedText: "error",
	}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// Get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 200, w.Code, "request should succeed")
	token := w.Body.String()

	// Make sure we get error without first confirming auth request
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 404, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"request not yet confirmed"}`+"\n", w.Body.String())

	time.Sleep(tokenLifetime)

	// Confirm auth request expired
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 404, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"request expired"}`+"\n", w.Body.String())
}

func TestTelegramConfirmedRequest(t *testing.T) {
	m := &tgMock{
		t:            t,
		expectedText: "success",
	}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// Get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 200, w.Code, "request should succeed")
	token := w.Body.String()

	m.Lock()
	m.token = token
	m.Unlock()
	time.Sleep(pollInterval * 2)

	// The token should be confirmed by now
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 200, w.Code, "response code should be 200")

	info := struct {
		Name    string `name:"name"`
		ID      string `id:"id"`
		Picture string `json:"picture"`
	}{}
	err := json.NewDecoder(w.Body).Decode(&info)
	assert.Nil(t, err)

	assert.Equal(t, "Joe", info.Name)
	assert.Contains(t, info.ID, "telegram_")
	assert.Equal(t, "http://example.com/ava12345.png", info.Picture)

	// Test request has been invalidated
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 404, w.Code, "request should get revoked")
	assert.Equal(t, `{"error":"request expired"}`+"\n", w.Body.String())
}

func TestTelegramLogout(t *testing.T) {
	m := &tgMock{t: t}

	tg, cleanup := setupHandler(t, m)
	defer cleanup()

	// Same TestVerifyHandler_Logout
	handler := http.HandlerFunc(tg.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", nil)
	assert.Nil(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, 2, len(rr.Header()["Set-Cookie"]))

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	assert.Nil(t, err)
	assert.Equal(t, time.Time{}, c.Expires)

	c, err = request.Cookie("XSRF-TOKEN")
	assert.Nil(t, err)
	assert.Equal(t, time.Time{}, c.Expires)
}

func setupHandler(t *testing.T, m *tgMock) (tg *TelegramHandler, cleanup func()) {
	pollInterval = time.Millisecond * 10
	tokenLifetime = time.Millisecond * 100

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

type tgMock struct {
	t            *testing.T
	expectedText string
	token        string

	sync.Mutex
}

func (m *tgMock) GetUpdates(ctx context.Context) (*telegramUpdate, error) {
	m.Lock()
	if m.token != "" {
		m.Unlock()
		var upd telegramUpdate
		resp := fmt.Sprintf(getUpdatesResp, m.token)

		err := json.Unmarshal([]byte(resp), &upd)
		if err != nil {
			m.t.Fatal(err)
		}
		return &upd, nil
	}
	m.Unlock()

	return nil, errors.New("no updates")
}

func (m *tgMock) Avatar(ctx context.Context, userID int) (string, error) {
	assert.Equal(m.t, userID, 313131313)
	return "https://example.com/telegram/avatar.jpg", nil
}

func (m *tgMock) Send(ctx context.Context, userID int, text string) error {
	assert.Equal(m.t, userID, 313131313)
	assert.Equal(m.t, m.expectedText, text)
	return nil
}

//
func TestTgAPI_GetUpdates(t *testing.T) {
	tg, cleanup := prepareTgAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "", r.URL.Query().Get("offset"))
		fmt.Fprintf(w, getUpdatesResp, "token")
	}))
	defer cleanup()

	upd, err := tg.GetUpdates(context.Background())
	assert.Nil(t, err)

	assert.Len(t, upd.Result, 1)

	assert.Equal(t, 1001, tg.updateOffset)
	assert.Equal(t, "/start token", upd.Result[0].Message.Text)
}

func TestTgAPI_Send(t *testing.T) {
	tg, cleanup := prepareTgAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "123", r.URL.Query().Get("chat_id"))
		assert.Equal(t, "hello there", r.URL.Query().Get("text"))
	}))
	defer cleanup()

	err := tg.Send(context.Background(), 123, "hello there")
	assert.Nil(t, err)
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
			fmt.Fprint(w, profilePhotosResp)
			return
		}

		assert.Equal(t, "1", r.URL.Query().Get("file_id"))
		fmt.Fprint(w, getFileResp)

	}))
	defer cleanup()

	url, err := tg.Avatar(context.Background(), 123)
	assert.Nil(t, err)

	expected := fmt.Sprintf("%s/file/bot%s/photos/file_0.jpg", tg.endpoint, tg.token)
	assert.Equal(t, expected, url)
}

const errorResp = `{"ok":false,"error_code":400,"description":"Very bad request"}`

func TestTgAPI_Error(t *testing.T) {
	tg, cleanup := prepareTgAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, errorResp)
	}))
	defer cleanup()

	_, err := tg.GetUpdates(context.Background())
	assert.NotNil(t, err)
	assert.Equal(t, "failed to fetch updates: telegram returned error: Very bad request", err.Error())
}

func prepareTgAPI(t *testing.T, h http.HandlerFunc) (tg *tgAPI, cleanup func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.String(), "xxxsupersecretxxx")
		h(w, r)
	}))

	tg = &tgAPI{
		L:        t,
		endpoint: srv.URL,
		token:    "xxxsupersecretxxx",
	}

	return tg, srv.Close
}
