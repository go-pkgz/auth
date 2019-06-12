package provider

import (
	"crypto/sha1"
	"errors"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/rest"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

// DirectHandler implements non-oauth2 provider authorizing user in traditional way with storage
// with users and hashes
type DirectHandler struct {
	logger.L
	CredChecker  CredChecker
	ProviderName string
	TokenService TokenService
	Issuer       string
	AvatarSaver  AvatarSaver
}

// CredChecker defines interface to check credentials
type CredChecker interface {
	Check(user, password string) (ok bool, err error)
}

// CredCheckerFunc type is an adapter to allow the use of ordinary functions as CredsChecker.
type CredCheckerFunc func(user, password string) (ok bool, err error)

// Check calls f(user,passwd)
func (f CredCheckerFunc) Check(user, password string) (ok bool, err error) {
	return f(user, password)
}

// Name of the handler
func (p DirectHandler) Name() string { return p.ProviderName }

// LoginHandler checks "user" and "passwd" against data store and makes jwt if all passed
// GET /something?user=name&password=xyz&sess=[0|1]
func (p DirectHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	user, password := r.URL.Query().Get("user"), r.URL.Query().Get("passwd")
	aud := r.URL.Query().Get("aud")
	sessOnly := r.URL.Query().Get("sess") == "1"
	if p.CredChecker == nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError,
			errors.New("no credential checker"), "no credential checker")
		return
	}
	ok, err := p.CredChecker.Check(user, password)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to check user credentials")
		return
	}
	if !ok {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, nil, "incorrect user or password")
		return
	}
	u := token.User{
		Name: user,
		ID:   p.ProviderName + "_" + token.HashID(sha1.New(), user),
	}
	u, err = setAvatar(p.AvatarSaver, u)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "can't make token id")
		return
	}

	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Id:       cid,
			Issuer:   p.Issuer,
			Audience: aud,
		},
		SessionOnly: sessOnly,
	}

	if _, err = p.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}
	rest.RenderJSON(w, r, claims.User)
}

// AuthHandler doesn't do anything for direct login as it has no callbacks
func (p DirectHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {}

// LogoutHandler - GET /logout
func (p DirectHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	p.TokenService.Reset(w)
}
