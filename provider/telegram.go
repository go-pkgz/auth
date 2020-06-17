package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"github.com/go-pkgz/rest"
)

const iframeTemplate = `
<html>
<head>
<title>Login with Telegram</title>
</head>
<body>
<script async src="https://telegram.org/js/telegram-widget.js?9" 
	data-telegram-login="{{ .BotInfo.Username }}" data-size="large" 
	data-auth-url="{{ .RedirURL}}" 
	data-request-access="write">
</script>
<body>
</html>	
`

const telegramAPIGetMe = "https://api.telegram.org/bot%s/getMe"

// TelgramBotBasicInfo represents data returned from getMe API call
type TelegramBotBasicInfo struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type TelegramHandler struct {
	Params
	Token string
	// Website domain linked to the bot (using BotFather bot https://core.telegram.org/widgets/login#linking-your-domain-to-the-bot)
	BotInfo  TelegramBotBasicInfo
	RedirURL string
}

func (t TelegramHandler) Name() string {
	return t.BotInfo.Username
}

func (t TelegramHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	t.Logf("[DEBUG] login with telegram bot %s", t.Name())

	// make state (random) and store in session
	state, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to make oauth2 state")
		return
	}
	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}

	claims := token.Claims{
		Handshake: &token.Handshake{
			State: state,
			From:  r.URL.Query().Get("from"),
		},
		SessionOnly: r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0",
		StandardClaims: jwt.StandardClaims{
			Id:        cid,
			Audience:  r.URL.Query().Get("site"),
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
		},
	}

	if _, err := t.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	t.RedirURL = t.makeRedirURL(r.URL.Path)

	tmpl, err := template.New("iframe").Parse(iframeTemplate)
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to create template for iframe with telegram login")
		return
	}
	if err := tmpl.Execute(w, t); err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to execute template for iframe with telegram login")
	}

	return
}

func (t TelegramHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	oauthClaims, _, err := t.JwtService.Get(r)
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to get token")
		return
	}

	if oauthClaims.Handshake == nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusForbidden, nil, "invalid handshake token")
		return
	}

	// instead of state check hash received from telegram
	// check hash with bot token (https://core.telegram.org/widgets/login#checking-authorization)
	hash := r.URL.Query().Get("hash")
	var params []string
	for key, vals := range r.URL.Query() {
		if key == "hash" {
			continue
		}
		params = append(params, strings.Join(append([]string{key}, vals...), "="))
	}
	sort.Sort(sort.StringSlice(params))
	dataCheckString := strings.Join(params, "\n")
	secretKey := sha256.Sum256([]byte(t.Token))
	mac := hmac.New(sha256.New, secretKey[:])
	mac.Write([]byte(dataCheckString))

	if hex.EncodeToString(mac.Sum(nil)) != hash {
		rest.SendErrorJSON(w, r, t.L, http.StatusForbidden, nil, "data integrity failure: hash doesn't match data-check-string")
		return
	}

	u := token.User{
		Name: strings.Join([]string{r.URL.Query().Get("first_name"),
			r.URL.Query().Get("last_name")}, " "),
		Picture: r.URL.Query().Get("photo_url"),
		ID:      "tgid_" + r.URL.Query().Get("id"),
	}
	u, err = setAvatar(t.AvatarSaver, u)
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}
	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Issuer:   t.Issuer,
			Id:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: oauthClaims.SessionOnly,
	}

	if _, err = t.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	t.Logf("[DEBUG] user info %+v", u)

	// redirect to back url if presented in login query params
	if oauthClaims.Handshake != nil && oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, r, &u)
}

func (t TelegramHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, _, err := t.JwtService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, t.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	t.JwtService.Reset(w)
}

func initTelegramAuthHandler(p Params, token string) TelegramHandler {
	if p.L == nil {
		p.L = logger.NoOp
	}

	th := TelegramHandler{Params: p}
	th.Token = token

	var err error
	th.BotInfo, err = getBotDetails(token)
	if err != nil {
		th.L.Logf("[WARN] failed to get bot details using token: %s", err.Error())
		// th.L.Logf("[WARN] check bot")
	}

	p.Logf("[DEBUG] created %s auth handler for Telegram Bot username=%s (id=%s), redir=%s",
		th.Name(), th.BotInfo.ID, th.makeRedirURL("/{route}/"+th.Name()+"/"))

	return th
}

func getBotDetails(token string) (TelegramBotBasicInfo, error) {

	c := &http.Client{Timeout: 10 * time.Second}

	resp, err := c.Get(fmt.Sprintf(telegramAPIGetMe, token))
	if err != nil {
		return TelegramBotBasicInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return TelegramBotBasicInfo{}, fmt.Errorf("telegram api call failed with status code %d", resp.StatusCode)
	}

	d := struct {
		Ok     bool                 `json:"ok"`
		Result TelegramBotBasicInfo `json:"result"`
	}{}

	if err = json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return TelegramBotBasicInfo{}, err
	}

	if !d.Ok {
		return TelegramBotBasicInfo{}, fmt.Errorf("no bot found")
	}

	return d.Result, nil
}

func (t *TelegramHandler) makeRedirURL(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimRight(t.URL, "/") + strings.TrimRight(newPath, "/") + urlCallbackSuffix
}
