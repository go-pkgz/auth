package provider

import (
	"bytes"
	"crypto/sha1"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/rest"
	"github.com/pkg/errors"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

var msgTemplateRedirect = ` Confirmation for {{.User}} {{.Address}}, site {{.Site}}, from {{.From}} Token: {{.Token}} `

// VerifyRedirectHandler implements non-oauth2 provider authorizing users with some confirmation.
// can be email, IM or anything else implementing Sender interface
type VerifyRedirectHandler struct {
	logger.L
	ProviderName string
	TokenService VerifTokenService
	Issuer       string
	AvatarSaver  AvatarSaver
	Sender       Sender
	Template     string
	UseGravatar  bool
}

// Name of the handler
func (e VerifyRedirectHandler) Name() string { return e.ProviderName }

// LoginHandler gets name and address from query, makes confirmation token and sends it to user.
// In case if confirmation token presented in the query uses it to create auth token
func (e VerifyRedirectHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {

	// GET /login?site=site&user=name&address=someone@example.com
	tkn := r.URL.Query().Get("token")
	if tkn == "" { // no token, ask confirmation via email
		e.sendConfirmation(w, r)
		return
	}

	// confirmation token presented
	// GET /login?token=confirmation-jwt&sess=1&from=callback_url
	confClaims, err := e.TokenService.Parse(tkn)
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusForbidden, err, "failed to verify confirmation token")
		return
	}

	if e.TokenService.IsExpired(confClaims) {
		rest.SendErrorJSON(w, r, e.L, http.StatusForbidden, errors.New("expired"), "failed to verify confirmation token")
		return
	}

	elems := strings.Split(confClaims.Handshake.ID, "::")
	if len(elems) != 2 {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, errors.New(confClaims.Handshake.ID), "invalid handshake token")
		return
	}
	user, address := elems[0], elems[1]
	sessOnly := r.URL.Query().Get("sess") == "1"

	u := token.User{
		Name: user,
		ID:   e.ProviderName + "_" + token.HashID(sha1.New(), address),
	}
	// try to get gravatar for email
	if e.UseGravatar && strings.Contains(address, "@") { // TODO: better email check to avoid silly hits to gravatar api
		if picURL, e := avatar.GetGravatarURL(address); e == nil {
			u.Picture = picURL
		}
	}

	if u, err = setAvatar(e.AvatarSaver, u, &http.Client{Timeout: 5 * time.Second}); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't make token id")
		return
	}

	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Id:       cid,
			Issuer:   e.Issuer,
			Audience: confClaims.Audience,
		},
		SessionOnly: sessOnly,
	}

	if _, err = e.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}
	if confClaims.Handshake != nil && confClaims.Handshake.From != "" {
		http.Redirect(w, r, confClaims.Handshake.From, http.StatusFound)
		return
	}
	rest.RenderJSON(w, r, claims.User)
}

// GET /login?site=site&user=name&address=someone@example.com
func (e VerifyRedirectHandler) sendConfirmation(w http.ResponseWriter, r *http.Request) {
	user, address := r.URL.Query().Get("user"), r.URL.Query().Get("address")
	if user == "" || address == "" {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, errors.New("wrong request"), "can't get user and address")
		return
	}
	claims := token.Claims{
		Handshake: &token.Handshake{
			State: "",
			From:  r.URL.Query().Get("from"),
			ID:    user + "::" + address,
		},
		SessionOnly: r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0",
		StandardClaims: jwt.StandardClaims{
			Audience:  r.URL.Query().Get("site"),
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
			Issuer:    e.Issuer,
		},
	}

	tkn, err := e.TokenService.Token(claims)
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusForbidden, err, "failed to make login token")
		return
	}

	tmpl := msgTemplateRedirect
	if e.Template != "" {
		tmpl = e.Template
	}
	emailTmpl, err := template.New("confirm").Parse(tmpl)
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't parse confirmation template")
		return
	}

	tmplData := struct {
		User    string
		Address string
		Token   string
		Site    string
		From    string
	}{
		User:    user,
		Address: address,
		Token:   tkn,
		Site:    r.URL.Query().Get("site"),
		From:    r.URL.Query().Get("from"),
	}
	buf := bytes.Buffer{}
	if err = emailTmpl.Execute(&buf, tmplData); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't execute confirmation template")
		return
	}

	if err := e.Sender.Send(address, buf.String()); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to send confirmation")
		return
	}

	rest.RenderJSON(w, r, rest.JSON{"user": user, "address": address})
}

// AuthHandler doesn't do anything for direct login as it has no callbacks
func (e VerifyRedirectHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {}

// LogoutHandler - GET /logout
func (e VerifyRedirectHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	e.TokenService.Reset(w)
}
