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

// TODO split those
// Fix race
func TestTelegramProvider(t *testing.T) {
	servedToken := ""
	seenError := false
	seenSuccess := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.Contains(r.URL.Path, "xxxsupersecretxxx"))

		if strings.Contains(r.URL.Path, "sendMessage") {
			assert.Equal(t, "313131313", r.URL.Query().Get("chat_id"))

			if r.URL.Query().Get("text") == "error" {
				seenError = true
			}
			if r.URL.Query().Get("text") == "success" {
				seenSuccess = true
			}
		} else if strings.Contains(r.URL.Path, "getUpdates") {
			if servedToken != "" {
				tmpl, _ := template.New("").Parse(responseTmpl)
				err := tmpl.Execute(w, servedToken)
				assert.Nil(t, err)
				return
			}

			// Should not provide offset until first response
			assert.Equal(t, "", r.URL.Query().Get("offset"))

		} else {
			t.Fatal("unexpected request url: ", r.URL.String())
		}
	}))

	defer server.Close()

	tg := &TelegramHandler{
		ProviderName:  "telegram",
		TelegramToken: "xxxsupersecretxxx",
		TelegramURL:   server.URL,
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		err := tg.Run(ctx)
		if err != context.Canceled {
			t.Error("Unexpected error: ", err)
		}
	}()
	time.Sleep(50 * time.Millisecond)

	// Get token
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 200, w.Code, "response code should be 200")
	token := w.Body.String()

	// Make sure it's invalid without confirmation
	r = httptest.NewRequest("GET", fmt.Sprintf("/?token=%s", token), nil)
	w = httptest.NewRecorder()
	tg.LoginHandler(w, r)

	assert.Equal(t, 404, w.Code, "response code should be 404")
	assert.Equal(t, `{"error":"token not yet confirmed"}`+"\n", w.Body.String())

	servedToken = "invalid token"
	time.Sleep(time.Second * 2)
	assert.True(t, seenError)

	servedToken = token
	time.Sleep(time.Second * 2)
	assert.True(t, seenSuccess)

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
