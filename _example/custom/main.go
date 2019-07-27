package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-pkgz/auth/provider"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/token"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/generates"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"

	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/store"
)

func main() {
	srv := initCustomProvider()

	opts := auth.Opts{
		SecretReader: token.SecretFunc(func() (string, error) { // secret key for JWT
			return "secret", nil
		}),
		TokenDuration:  time.Minute * 5,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-demo-app",
		URL:            "http://127.0.0.1:8080",
		AvatarStore:    avatar.NewLocalFS("/tmp"),
	}

	// create auth service with providers
	service := auth.NewService(opts)

	// retrieve auth middleware
	m := service.Middleware()

	// setup http server
	router := chi.NewRouter()
	router.Get("/open", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Open")
	}) // open api
	router.With(m.Auth).Get("/private", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Private")
	}) // protected api

	// setup auth routes
	authRoutes, avaRoutes := service.Handlers()
	router.Mount("/auth", authRoutes)  // add auth handlers
	router.Mount("/avatar", avaRoutes) // add avatar handler

	copts := provider.CustomProviderOpt{
		WithLoginPage: true,
		Cid:           "cid",
	}
	service.StartCustomServer(context.Background(), srv, copts)

	log.Fatal(http.ListenAndServe(":8080", router))

}

func initCustomProvider() *server.Server {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))

	// client memory store
	clientStore := store.NewClientStore()
	clientStore.Set("cid", &models.Client{
		ID:     "cid",
		Secret: "csecret",
		Domain: "http://127.0.0.1:8080", //TODO should be the same as service.rootURL
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		if r.Form.Get("username") != "admin" || r.Form.Get("password") != "admin" {
			return "", fmt.Errorf("Wrong creds. Use: admin admin")
		}
		return "admin", nil
	})

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	return srv
}
