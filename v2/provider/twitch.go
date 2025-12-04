package provider

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/go-pkgz/auth/v2/token"
	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/twitch"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type twitchUser struct {
	Id              string `json:"id"`
	Login           string `json:"login,omitempty"`
	Name            string `json:"display_name,omitempty"`
	Email           string `json:"email,omitempty"`
	ProfileImageURL string `json:"profile_image_url,omitempty"`
}

type twitchRaw struct {
	Data []twitchUser `json:"data"`
}

// TwitchHandler implements login via Twitch
type TwitchHandler struct {
	Params
	endpoint oauth2.Endpoint
	infoURL  string
	scopes   []string
	mapUser  func(data []byte) token.User
}

func (h TwitchHandler) Name() string {
	return "twitch"
}

func (h TwitchHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	h.Logf("[DEBUG] login with %s", h.Name())

	state, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to make oauth2 state")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}

	claims := token.Claims{
		Handshake: &token.Handshake{
			State: state,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        cid,
			Audience:  jwt.ClaimStrings{r.URL.Query().Get("site")},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		},
	}

	if _, err = h.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	loginURL, err := h.redirectURL(r, state)
	if err != nil {
		errMsg := fmt.Sprintf("prepare login url for [%s] provider failed", h.Name())
		h.Logf("[ERROR] %s", errMsg)
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, errMsg)
		return
	}
	h.Logf("[DEBUG] login url %s, claims=%+v", loginURL, claims)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h TwitchHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "read callback response from data failed")
		return
	}

	state := r.FormValue("state")
	code := r.FormValue("code")

	oauthClaims, _, err := h.JwtService.Get(r)
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to get token")
		return
	}

	if oauthClaims.Handshake == nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusForbidden, nil, "invalid handshake token")
		return
	}

	if oauthClaims.Handshake.State != state {
		rest.SendErrorJSON(w, r, h.L, http.StatusForbidden, nil, "unexpected state")
		return
	}

	accessToken, err := h.requestAccessToken(r, code)
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to obtain access token")
		return
	}

	h.Logf("[DEBUG] response data %+v", accessToken)

	userInfo, err := h.requestUserInfo(accessToken)
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "user not found")
		return
	}

	u := h.mapUser(userInfo)

	u, err = setAvatar(h.AvatarSaver, u, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}

	claims := token.Claims{
		User: &u,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   h.Issuer,
			ID:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: false,
	}

	if _, err := h.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	rest.RenderJSON(w, claims.User)
}

func (h TwitchHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, _, err := h.JwtService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, h.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	h.JwtService.Reset(w)
}

// redirectURL builds a redirect URL to the Twitch login page
func (h TwitchHandler) redirectURL(r *http.Request, state string) (string, error) {
	authURL, err := url.Parse(h.endpoint.AuthURL)
	if err != nil {
		return "", err
	}

	query := authURL.Query()
	query.Set("client_id", h.Cid)
	query.Set("response_type", "code")
	query.Set("scope", "user:read:email")
	query.Set("redirect_uri", makeRedirectURL(h.URL, r.URL.Path))
	query.Set("force_verify", "false")
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

// requestUserInfo requests information about the user
// https://dev.twitch.tv/docs/api/reference/#get-users
func (h TwitchHandler) requestUserInfo(accessToken *AccessTokenResponse) ([]byte, error) {
	client := http.Client{Timeout: time.Second * 10}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.infoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Client-ID", h.Cid)
	req.Header.Add("Authorization", "Bearer "+accessToken.AccessToken)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err = res.Body.Close(); err != nil {
			h.L.Logf("[ERROR] close request body failed when get user info: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s user info error: %s", h.Name(), res.Status)
	}

	body, err := io.ReadAll(res.Body)

	return body, err
}

// requestAccessToken requests an access token
// https://dev.twitch.tv/docs/api/get-started/#get-an-oauth-token
func (h TwitchHandler) requestAccessToken(r *http.Request, code string) (*AccessTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", h.Cid)
	data.Set("client_secret", h.Csecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", makeRedirectURL(h.URL, r.URL.Path))

	client := http.Client{Timeout: time.Second * 10}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var result AccessTokenResponse
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling data from %s service response failed: %w", h.Name(), err)
	}

	defer func() {
		if err = res.Body.Close(); err != nil {
			h.L.Logf("[ERROR] close request body failed when get access token: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s token service error: %s", h.Name(), res.Status)
	}

	return &result, err
}

// NewTwitch makes Twitch OAuth2 provider
func NewTwitch(p Params) TwitchHandler {
	return TwitchHandler{
		Params:   p,
		endpoint: twitch.Endpoint,
		infoURL:  "https://api.twitch.tv/helix/users", //https://dev.twitch.tv/docs/api/reference/#get-users
		scopes:   []string{"user:read:email"},
		mapUser: func(data []byte) token.User {
			userInfo := token.User{}
			raw := twitchRaw{}
			if err := json.Unmarshal(data, &raw); err == nil {
				userInfo.ID = "twitch_" + token.HashID(sha1.New(), raw.Data[0].Id)
				userInfo.Name = raw.Data[0].Name
				userInfo.Picture = raw.Data[0].ProfileImageURL

				if userInfo.Name == "" {
					userInfo.Name = raw.Data[0].Login
				}

				if userInfo.Name == "" {
					userInfo.Name = raw.Data[0].Email
				}

				if userInfo.Name == "" {
					userInfo.Name = "twitch_" + raw.Data[0].Id
				}
			}
			return userInfo
		},
	}
}
