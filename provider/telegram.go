package provider

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	authtoken "github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/rest"
	"github.com/pkg/errors"
)

// TelegramHandler implements login via telegram
type TelegramHandler struct {
	logger.L

	ProviderName         string
	TelegramToken        string
	TelegramURL          string
	ErrorMsg, SuccessMsg string

	TokenService TokenService

	mu     sync.Mutex           // Guard for the map below
	tokens map[string]*userInfo // Tokens waiting for confirmation
}

type userInfo struct {
	ID   int
	Name string
}

// Run starts processing login requests sent in Telegram
// Blocks caller
func (t *TelegramHandler) Run(ctx context.Context) error {
	// Initialization
	t.tokens = make(map[string]*userInfo)
	if t.TelegramURL == "" {
		t.TelegramURL = "https://api.telegram.org"
	}

	ticker := time.NewTicker(time.Second)
	offset := 0

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		case <-ticker.C:
			var err error
			offset, err = t.processUpdates(offset)
			if err != nil {
				t.Logf("Error while processing updates: %v", err)
				continue
			}
		}
	}

}

type telegramUpdate struct {
	OK     bool `json:"ok"`
	Result []struct {
		UpdateID int `json:"update_id"`
		Message  struct {
			Chat struct {
				ID   int    `json:"id"`
				Name string `json:"first_name"`
				Type string `json:"type"`
			} `json:"chat"`
			Text string `json:"text"`
		} `json:"message"`
	} `json:"result"`
}

// processUpdates processes a batch of updates from telegram servers
// Returns offset for subsequest calls
func (t *TelegramHandler) processUpdates(offset int) (int, error) {
	urlFormat := `%s/bot%s/getUpdates?allowed_updates=["message"]`
	if offset != 0 {
		urlFormat += fmt.Sprintf("&offset=%d", offset) // See core.telegram.org/bots/api#getupdates
	}

	resp, err := http.Get(fmt.Sprintf(urlFormat, t.TelegramURL, t.TelegramToken))
	if err != nil {
		return offset, errors.Wrap(err, "can't initialize telegram notifications")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return offset, errors.Errorf("unexpected telegram status code %d", resp.StatusCode)
	}

	var upd telegramUpdate

	if err = json.NewDecoder(resp.Body).Decode(&upd); err != nil {
		return offset, errors.Wrap(err, "can't decode response")
	}

	if !upd.OK {
		return offset, errors.Errorf("apparently response is not ok")
	}

	offset = t.handleUpdates(upd, offset)

	return offset, nil
}

func (t *TelegramHandler) handleUpdates(upd telegramUpdate, offset int) int {
	for _, update := range upd.Result {
		if update.UpdateID >= offset {
			offset = update.UpdateID + 1
		}

		if update.Message.Chat.Type != "private" {
			continue
		}

		if !strings.HasPrefix(update.Message.Text, "/start ") {
			err := t.send(update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				t.Logf("failed to notify telegram peer: ", err)
			}
			continue
		}

		token := strings.TrimPrefix(update.Message.Text, "/start ")

		t.mu.Lock()
		if _, ok := t.tokens[token]; !ok { // No such token
			t.mu.Unlock()
			err := t.send(update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				t.Logf("failed to notify telegram peer: ", err)
			}
			continue
		}

		t.tokens[token] = &userInfo{
			ID:   update.Message.Chat.ID,
			Name: update.Message.Chat.Name,
		}
		t.mu.Unlock()

		err := t.send(update.Message.Chat.ID, t.SuccessMsg)
		if err != nil {
			t.Logf("failed to notify telegram peer: ", err)
		}
	}

	return offset
}

// Send a text message to a Telegram peer
func (t *TelegramHandler) send(id int, msg string) error {
	urlFormat := `%s/bot%s/sendMessage?chat_id=%d&text=%s`
	resp, err := http.Get(fmt.Sprintf(urlFormat, t.TelegramURL, t.TelegramToken, id, msg))
	if err != nil {
		return errors.Wrap(err, "failed to send message")
	}
	defer resp.Body.Close()

	return nil
}

// Name of the handler
func (t *TelegramHandler) Name() string { return t.ProviderName }

// LoginHandler generates and verifies login requests
func (t *TelegramHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	queryToken := r.URL.Query().Get("token")
	if queryToken == "" {
		// GET /login (No token supplied)
		// Generate and send token
		token, err := randToken()
		if err != nil {
			rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to generate code")
		}

		t.mu.Lock()
		t.tokens[token] = nil // Mark token as not yet confirmed
		t.mu.Unlock()

		fmt.Fprint(w, token)
		return
	}

	// GET /login?token=blah
	t.mu.Lock()
	userInfo := t.tokens[queryToken]
	t.mu.Unlock()

	if userInfo == nil {
		rest.SendErrorJSON(w, r, nil, http.StatusNotFound, nil, "token not yet confirmed")
		return
	}

	u := authtoken.User{
		Name: userInfo.Name,
		ID:   t.ProviderName + "_" + authtoken.HashID(sha1.New(), fmt.Sprint(userInfo.ID)),
	}

	claims := authtoken.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Id:     queryToken,
			Issuer: t.ProviderName,
		},
		SessionOnly: false, // TODO
	}

	if _, err := t.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	rest.RenderJSON(w, r, claims.User)
}

// AuthHandler does nothing since we're don't have any callbacks
func (t *TelegramHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {}

// LogoutHandler - GET /logout
func (t *TelegramHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	t.TokenService.Reset(w)
}
