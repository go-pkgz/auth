package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/rest"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/token"
)

// Service represents oauth2 provider
type Service struct {
	Params
	Name        string
	RedirectURL string
	InfoURL     string
	Endpoint    oauth2.Endpoint
	Scopes      []string
	MapUser     func(userData, []byte) token.User // map info from InfoURL to User
	conf        oauth2.Config
}

// Params to make initialized and ready to use provider
type Params struct {
	URL         string
	JwtService  *token.Service
	AvatarProxy *avatar.Proxy
	Cid         string
	Csecret     string
	Issuer      string
}

type userData map[string]interface{}

func (u userData) value(key string) string {
	// json.Unmarshal converts json "null" value to go's "nil", in this case return empty string
	if val, ok := u[key]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// initService makes oauth2 service for given provider
func initService(p Params, service Service) Service {
	log.Printf("[INFO] init oauth2 service %s", service.Name)
	service.Params = p
	service.conf = oauth2.Config{
		ClientID:     service.Cid,
		ClientSecret: service.Csecret,
		RedirectURL:  service.RedirectURL,
		Scopes:       service.Scopes,
		Endpoint:     service.Endpoint,
	}

	log.Printf("[DEBUG] created %s oauth2, id=%s, redir=%s, endpoint=%s",
		service.Name, service.Cid, service.Endpoint, service.RedirectURL)
	return service
}

// Handler returns auth routes for given provider
func (p Service) Handler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/login") {
		p.loginHandler(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/callback") {
		p.authHandler(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/logout") {
		p.LogoutHandler(w, r)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

// loginHandler - GET /login?from=redirect-back-url&site=siteID&session=1
func (p Service) loginHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("[DEBUG] login with %s", p.Name)
	// make state (random) and store in session
	state, err := p.randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to make oauth2 state")
		return
	}

	cid, err := p.randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to make claim's id")
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

	if err := p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// return login url
	loginURL := p.conf.AuthCodeURL(state)
	log.Printf("[DEBUG] login url %s, claims=%+v", loginURL, claims)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// authHandler fills user info and redirects to "from" url. This is callback url redirected locally by browser
// GET /callback
func (p Service) authHandler(w http.ResponseWriter, r *http.Request) {
	oauthClaims, _, err := p.JwtService.Get(r)
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to get token")
		return
	}

	if oauthClaims.Handshake == nil {
		rest.SendErrorJSON(w, r, http.StatusForbidden, err, "invalid handshake token")
		return
	}

	retrievedState := oauthClaims.Handshake.State
	if retrievedState == "" || retrievedState != r.URL.Query().Get("state") {
		http.Error(w, fmt.Sprintf("unexpected state %v", retrievedState), http.StatusUnauthorized)
		return
	}

	log.Printf("[DEBUG] token with state %s", retrievedState)
	tok, err := p.conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "exchange failed")
		return
	}

	client := p.conf.Client(context.Background(), tok)
	uinfo, err := client.Get(p.InfoURL)
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusBadRequest, err, fmt.Sprintf("failed to get client info via %s", p.InfoURL))
		return
	}

	defer func() {
		if e := uinfo.Body.Close(); e != nil {
			log.Printf("[WARN] failed to close response body, %s", e)
		}
	}()

	data, err := ioutil.ReadAll(uinfo.Body)
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to read user info")
		return
	}

	jData := map[string]interface{}{}
	if e := json.Unmarshal(data, &jData); e != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to unmarshal user info")
		return
	}
	log.Printf("[DEBUG] got raw user info %+v", jData)

	u := p.MapUser(jData, data)
	u = p.setAvatar(u)

	cid, err := p.randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}
	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Issuer:   p.Issuer,
			Id:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: oauthClaims.SessionOnly,
	}

	if err = p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "failed to save user info")
		return
	}

	log.Printf("[DEBUG] user info %+v", u)

	// redirect to back url if presented in login query params
	if oauthClaims.Handshake != nil && oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, r, &u)
}

// setAvatar saves avatar and puts proxied URL to u.Picture
func (p Service) setAvatar(u token.User) token.User {
	if p.AvatarProxy != nil {
		if avatarURL, e := p.AvatarProxy.Put(u); e == nil {
			u.Picture = avatarURL
		} else {
			log.Printf("[WARN] failed to set avatar for %+v, %+v", u, e)
		}
	}
	return u
}

// LogoutHandler - GET /logout
func (p Service) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	p.JwtService.Reset(w)
	log.Printf("[DEBUG] logout")
}

func (p Service) randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrap(err, "can't get random")
	}
	s := sha1.New()
	if _, err := s.Write(b); err != nil {
		return "", errors.Wrap(err, "can't write randoms to sha1")
	}
	return fmt.Sprintf("%x", s.Sum(nil)), nil
}
