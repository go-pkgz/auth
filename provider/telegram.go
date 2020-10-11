package provider

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
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
	ErrorMsg, SuccessMsg string

	TokenService TokenService
	AvatarSaver  AvatarSaver
	Telegram     TelegramAPI

	requests tgAuthRequests
}

type tgAuthRequests struct {
	sync.RWMutex
	data map[string]tgAuthRequest
}

type tgAuthRequest struct {
	confirmed bool // whether login request has been confirmed and user info set
	expires   time.Time
	user      *authtoken.User
}

// TelegramAPI is used for interacting with telegram API
type TelegramAPI interface {
	GetUpdates(ctx context.Context) (*telegramUpdate, error)
	Avatar(ctx context.Context, userID int) (string, error)
	Send(ctx context.Context, id int, text string) error
}

// changed in tests
var tgPollInterval = time.Second

// Run starts processing login requests sent in Telegram
// Blocks caller
func (t *TelegramHandler) Run(ctx context.Context) error {
	// Initialization
	t.requests.Lock()
	t.requests.data = make(map[string]tgAuthRequest)
	t.requests.Unlock()

	ticker := time.NewTicker(tgPollInterval)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		case <-ticker.C:
			err := t.processUpdates(ctx)
			if err != nil {
				t.Logf("Error while processing updates: %v", err)
				continue
			}

			// Purge expired requests
			now := time.Now()
			t.requests.Lock()
			for key, req := range t.requests.data {
				if now.After(req.expires) {
					delete(t.requests.data, key)
				}
			}
			t.requests.Unlock()
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
func (t *TelegramHandler) processUpdates(ctx context.Context) error {
	updates, err := t.Telegram.GetUpdates(ctx)
	if err != nil {
		return err
	}

	for _, update := range updates.Result {
		if update.Message.Chat.Type != "private" {
			continue
		}

		if !strings.HasPrefix(update.Message.Text, "/start ") {
			err := t.Telegram.Send(ctx, update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				t.Logf("failed to notify telegram peer: %v", err)
			}
			continue
		}

		token := strings.TrimPrefix(update.Message.Text, "/start ")

		t.requests.RLock()
		authRequest, ok := t.requests.data[token]
		if !ok { // No such token
			t.requests.RUnlock()
			err := t.Telegram.Send(ctx, update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				t.Logf("failed to notify telegram peer: %v", err)
			}
			continue
		}
		t.requests.RUnlock()

		avatarURL, err := t.Telegram.Avatar(ctx, update.Message.Chat.ID)
		if err != nil {
			t.Logf("failed to get user avatar: %v", err)
			continue
		}

		id := t.ProviderName + "_" + authtoken.HashID(sha1.New(), fmt.Sprint(update.Message.Chat.ID))

		authRequest.confirmed = true
		authRequest.user = &authtoken.User{
			ID:      id,
			Name:    update.Message.Chat.Name,
			Picture: avatarURL,
		}

		t.requests.Lock()
		t.requests.data[token] = authRequest
		t.requests.Unlock()

		err = t.Telegram.Send(ctx, update.Message.Chat.ID, t.SuccessMsg)
		if err != nil {
			t.Logf("failed to notify telegram peer: %v", err)
		}
	}

	return nil
}

// Name of the handler
func (t *TelegramHandler) Name() string { return t.ProviderName }

// Default token lifetime. Changed in tests
var tgAuthRequestLifetime = time.Minute * 10

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

		t.requests.Lock()
		t.requests.data[token] = tgAuthRequest{
			expires: time.Now().Add(tgAuthRequestLifetime),
		}
		t.requests.Unlock()

		fmt.Fprint(w, token)
		return
	}

	// GET /login?token=blah
	t.requests.RLock()
	authRequest, ok := t.requests.data[queryToken]
	t.requests.RUnlock()

	if !ok || time.Now().After(authRequest.expires) {
		t.requests.Lock()
		delete(t.requests.data, queryToken)
		t.requests.Unlock()

		rest.SendErrorJSON(w, r, nil, http.StatusNotFound, nil, "request expired")
		return
	}

	if !authRequest.confirmed {
		rest.SendErrorJSON(w, r, nil, http.StatusNotFound, nil, "request not yet confirmed")
		return
	}

	u, err := setAvatar(t.AvatarSaver, *authRequest.user, &http.Client{Timeout: 5 * time.Second})
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
	t.requests.Lock()
	defer t.requests.Unlock()
	delete(t.requests.data, queryToken)
}

// AuthHandler does nothing since we're don't have any callbacks
func (t *TelegramHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {}

// LogoutHandler - GET /logout
func (t *TelegramHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	t.TokenService.Reset(w)
}

// tgAPI implements TelegramAPI
type tgAPI struct {
	logger.L
	endpoint     string
	token        string
	updateOffset int
}

// NewTelegramAPI returns initialized TelegramAPI implementation
func NewTelegramAPI(token string, l logger.L) TelegramAPI {
	return &tgAPI{
		L:        l,
		endpoint: "https://api.telegram.org",
		token:    token,
	}
}

// GetUpdates fetches incoming updates
func (t *tgAPI) GetUpdates(ctx context.Context) (*telegramUpdate, error) {
	url := `getUpdates?allowed_updates=["message"]`
	if t.updateOffset != 0 {
		url += fmt.Sprintf("&offset=%d", t.updateOffset) // See core.telegram.org/bots/api#getupdates
	}

	var result telegramUpdate

	err := t.request(ctx, url, &result)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch updates")
	}

	for _, u := range result.Result {
		if u.UpdateID >= t.updateOffset {
			t.updateOffset = u.UpdateID + 1
		}
	}

	return &result, err
}

// Send sends a message to telegram peer
func (t *tgAPI) Send(ctx context.Context, id int, msg string) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage?chat_id=%d&text=%s", t.endpoint, t.token, id, neturl.PathEscape(msg))

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
		return errors.Errorf("telegram returned %d status code", resp.StatusCode)
	}

	return nil
}

// Avatar returns URL to user avatar
func (t *tgAPI) Avatar(ctx context.Context, id int) (string, error) {
	// Get profile pictures
	url := fmt.Sprintf(`getUserProfilePhotos?user_id=%d`, id)

	var profilePhotos = struct {
		Result struct {
			Photos [][]struct {
				ID string `json:"file_id"`
			} `json:"photos"`
		} `json:"result"`
	}{}

	err := t.request(ctx, url, &profilePhotos)
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
	url = fmt.Sprintf(`getFile?file_id=%s`, fileID)

	var fileMetadata = struct {
		Result struct {
			Path string `json:"file_path"`
		} `json:"result"`
	}{}

	err = t.request(ctx, url, &fileMetadata)
	if err != nil {
		return "", err
	}

	avatarURL := fmt.Sprintf("%s/file/bot%s/%s", t.endpoint, t.token, fileMetadata.Result.Path)

	return avatarURL, nil
}

func (t *tgAPI) request(ctx context.Context, method string, data interface{}) error {
	url := fmt.Sprintf("%s/bot%s/%s", t.endpoint, t.token, method)

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
		return t.parseError(resp.Body)
	}

	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return errors.Wrap(err, "can't decode json response")
	}

	return nil
}

func (t *tgAPI) parseError(r io.Reader) error {
	var tgErr = struct {
		Description string `json:"description"`
	}{}

	if err := json.NewDecoder(r).Decode(&tgErr); err != nil {
		return errors.Wrap(err, "can't decode error")
	}

	return errors.Errorf("telegram returned error: %v", tgErr.Description)
}
