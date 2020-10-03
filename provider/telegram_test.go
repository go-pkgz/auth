package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
	"time"

	authtoken "github.com/go-pkgz/auth/token"
	"github.com/stretchr/testify/assert"
)

func TestTelegramUnconfirmedRequest(t *testing.T) {
	server, respond := setupServer(t)
	defer server.Close()

	tg, cleanup := setupHandler(t, server.URL)
	defer cleanup()

	// Get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 200, w.Code, "request should succeed")
	token := w.Body.String()

	_ = respond("blah") // Simulate getUpdates with invalid user command
	hr := respond("")   // Next request should be sendMessage
	assert.Equal(t, "313131313", hr.URL.Query().Get("chat_id"))
	assert.Equal(t, "error", hr.URL.Query().Get("text"))

	// Make sure we get error without first confirming auth request
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 404, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"token not yet confirmed"}`+"\n", w.Body.String())
}

func TestTelegramConfirmedRequest(t *testing.T) {
	server, respond := setupServer(t)
	defer server.Close()

	tg, cleanup := setupHandler(t, server.URL)
	defer cleanup()

	// Get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 200, w.Code, "request should succeed")
	token := w.Body.String()

	_ = respond(token) // Simulate an update where user send valid token
	hr := respond("")  // Next request should be sendMessage
	assert.Equal(t, "313131313", hr.URL.Query().Get("chat_id"))
	assert.Equal(t, "success", hr.URL.Query().Get("text"))

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
	assert.Equal(t, "", info.Picture) // Not yet implemented
}

func TestTelegramLogout(t *testing.T) {
	server, _ := setupServer(t)
	defer server.Close()

	tg, cleanup := setupHandler(t, server.URL)
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

const responseTmpl = `{
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
            "text": "/start {{.}}",
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

// setupServer initializes a mock Telegram server that captures incoming requests
func setupServer(t *testing.T) (srv *httptest.Server, respond func(string) *http.Request) {
	reqChan := make(chan string)
	respChan := make(chan *http.Request)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := <-reqChan
		respChan <- r

		assert.True(t, strings.Contains(r.URL.Path, "xxxsupersecretxxx"))

		if strings.Contains(r.URL.Path, "sendMessage") {
			return
		}

		if token != "" {
			tmpl, _ := template.New("").Parse(responseTmpl)
			err := tmpl.Execute(w, token)
			assert.Nil(t, err)
			return
		}
	}))

	respond = func(token string) *http.Request {
		reqChan <- token
		return <-respChan
	}

	return
}

func setupHandler(t *testing.T, serverURL string) (tg *TelegramHandler, cleanup func()) {
	tg = &TelegramHandler{
		ProviderName:  "telegram",
		TelegramToken: "xxxsupersecretxxx",
		TelegramURL:   serverURL,
		ErrorMsg:      "error",
		SuccessMsg:    "success",

		L: t,
		TokenService: authtoken.NewService(authtoken.Opts{
			SecretReader:   authtoken.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
	}

	assert.Equal(t, "telegram", tg.Name())

	ctx, cleanup := context.WithCancel(context.Background())
	go func() {
		err := tg.Run(ctx)
		if err != context.Canceled {
			t.Errorf("Unexpected error: %v", err)
		}
	}()
	time.Sleep(50 * time.Millisecond)

	return
}
