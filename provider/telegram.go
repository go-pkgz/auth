package provider

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
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
	AvatarSaver  AvatarSaver

	mu           sync.Mutex             // Guard for the map below
	authRequests map[string]authRequest // Tokens waiting for confirmation
}

type authRequest struct {
	confirmed bool // whether login request has been confirmed and userInfo set
	expires   time.Time
	user      *userInfo
}

type userInfo struct {
	ID     int
	Name   string
	Avatar string
}

// Run starts processing login requests sent in Telegram
// Blocks caller
func (t *TelegramHandler) Run(ctx context.Context) error {
	// Initialization
	t.mu.Lock()
	t.authRequests = make(map[string]authRequest)
	t.mu.Unlock()

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
			offset, err = t.processUpdates(ctx, offset)
			if err != nil {
				t.Logf("Error while processing updates: %v", err)
				continue
			}

			// Purge expired requests
			now := time.Now()
			t.mu.Lock()
			for key, req := range t.authRequests {
				if now.After(req.expires) {
					delete(t.authRequests, key)
				}
			}
			t.mu.Unlock()
		}
	}
}

type telegramUpdate struct {
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
func (t *TelegramHandler) processUpdates(ctx context.Context, offset int) (int, error) {
	url := fmt.Sprintf(`%s/bot%s/getUpdates?allowed_updates=["message"]`, t.TelegramURL, t.TelegramToken)
	if offset != 0 {
		url += fmt.Sprintf("&offset=%d", offset) // See core.telegram.org/bots/api#getupdates
	}
	var result telegramUpdate

	err := requestTelegram(ctx, url, &result)
	if err != nil {
		return offset, errors.Wrap(err, "failed to process update")
	}

	return t.handleUpdates(ctx, result, offset), nil
}

func (t *TelegramHandler) handleUpdates(ctx context.Context, upd telegramUpdate, offset int) int {
	for _, update := range upd.Result {
		if update.UpdateID >= offset {
			offset = update.UpdateID + 1
		}

		if update.Message.Chat.Type != "private" {
			continue
		}

		if !strings.HasPrefix(update.Message.Text, "/start ") {
			err := t.send(ctx, update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				t.Logf("failed to notify telegram peer: %v", err)
			}
			continue
		}

		token := strings.TrimPrefix(update.Message.Text, "/start ")

		t.mu.Lock()
		authRequest, ok := t.authRequests[token]
		if !ok { // No such token
			t.mu.Unlock()
			err := t.send(ctx, update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				t.Logf("failed to notify telegram peer: %v", err)
			}
			continue
		}
		t.mu.Unlock()

		avatarURL, err := t.getUserAvatar(ctx, update.Message.Chat.ID)
		if err != nil {
			t.Logf("failed to get user avatar: %v", err)
			continue
		}

		authRequest.confirmed = true
		authRequest.user = &userInfo{
			ID:     update.Message.Chat.ID,
			Name:   update.Message.Chat.Name,
			Avatar: avatarURL,
		}

		t.mu.Lock()
		t.authRequests[token] = authRequest
		t.mu.Unlock()

		err = t.send(ctx, update.Message.Chat.ID, t.SuccessMsg)
		if err != nil {
			t.Logf("failed to notify telegram peer: %v", err)
		}
	}

	return offset
}

// Send a text message to a Telegram peer
func (t *TelegramHandler) send(ctx context.Context, id int, msg string) error {
	url := fmt.Sprintf(`%s/bot%s/sendMessage?chat_id=%d&text=%s`, t.TelegramURL, t.TelegramToken, id, msg)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create sendMessage request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send message")
	}
	defer resp.Body.Close()

	return nil
}

func (t *TelegramHandler) getUserAvatar(ctx context.Context, id int) (string, error) {
	// Get profile pictures
	url := fmt.Sprintf(`%s/bot%s/getUserProfilePhotos?user_id=%d`, t.TelegramURL, t.TelegramToken, id)

	var profilePhotos = struct {
		Result struct {
			Photos [][]struct {
				ID string `json:"file_id"`
			} `json:"photos"`
		} `json:"result"`
	}{}

	err := requestTelegram(ctx, url, &profilePhotos)
	if err != nil {
		return "", err
	}

	// User does not have profile picture set or it is hidden in privacy settings
	if len(profilePhotos.Result.Photos) == 0 {
		return "", nil
	}

	// Get actual avatar url
	last := len(profilePhotos.Result.Photos[0]) - 1
	fileID := profilePhotos.Result.Photos[0][last].ID
	url = fmt.Sprintf(`%s/bot%s/getFile?file_id=%s`, t.TelegramURL, t.TelegramToken, fileID)

	var fileMetadata = struct {
		Result struct {
			Path string `json:"file_path"`
		} `json:"result"`
	}{}

	err = requestTelegram(ctx, url, &fileMetadata)
	if err != nil {
		return "", err
	}

	avatarURL := fmt.Sprintf("%s/file/bot%s/%s", t.TelegramURL, t.TelegramToken, fileMetadata.Result.Path)

	return avatarURL, nil
}

// little helper function to request telegram endpoints
func requestTelegram(ctx context.Context, url string, data interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return parseError(resp.Body)
	}

	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return errors.Wrap(err, "can't decode json response")
	}

	return nil
}

func parseError(r io.Reader) error {
	var tgErr = struct {
		Description string `json:"description"`
	}{}

	if err := json.NewDecoder(r).Decode(&tgErr); err != nil {
		return errors.Wrap(err, "can't decode error")
	}

	return errors.Errorf("telegram returned error: %v", tgErr.Description)
}

// Name of the handler
func (t *TelegramHandler) Name() string { return t.ProviderName }

// changed in tests
var tokenLifetime = time.Minute * 10

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
		t.authRequests[token] = authRequest{
			expires: time.Now().Add(tokenLifetime),
		}
		t.mu.Unlock()

		fmt.Fprint(w, token)
		return
	}

	// GET /login?token=blah
	t.mu.Lock()
	authRequest, ok := t.authRequests[queryToken]
	t.mu.Unlock()

	if !ok || time.Now().After(authRequest.expires) {
		delete(t.authRequests, queryToken)
		rest.SendErrorJSON(w, r, nil, http.StatusNotFound, nil, "request expired")
		return
	}

	if !authRequest.confirmed {
		rest.SendErrorJSON(w, r, nil, http.StatusNotFound, nil, "request not yet confirmed")
		return
	}

	u := authtoken.User{
		Name:    authRequest.user.Name,
		ID:      t.ProviderName + "_" + authtoken.HashID(sha1.New(), fmt.Sprint(authRequest.user.ID)),
		Picture: authRequest.user.Avatar,
	}

	u, err := setAvatar(t.AvatarSaver, u, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
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

	// Delete request
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.authRequests, queryToken)
}

// AuthHandler does nothing since we're don't have any callbacks
func (t *TelegramHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {}

// LogoutHandler - GET /logout
func (t *TelegramHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	t.TokenService.Reset(w)
}
