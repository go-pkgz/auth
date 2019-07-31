package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"text/template"
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
		// handle user-defined template
		// if not set: default template will be rendered
		LoginPageHandler: func(w http.ResponseWriter, r *http.Request) {
			userLoginTmpl, err := template.New("page").Parse(customTemplate)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}

			formData := struct{ Query string }{Query: r.URL.RawQuery}

			if err := userLoginTmpl.Execute(w, formData); err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
			return
		},
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
		Domain: "http://127.0.0.1:8080", // GetDomain() should deliver the same domain as in redir url
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

var customTemplate = `
			<html>
			<head>
			<title>Dev OAuth</title>
			</head>
			<body>
			<form action="/login/oauth/authorize?{{.Query}}" method="POST">
			<label>
				<span class="username-label">Username</span>
				<input
					class="username-input"
					type="text"
					name="username"
					value=""
					autofocus
				/>
			</label>
			<br>
			<label>
			<span class="username-label">Password</span>
			<input
				class="username-input"
				type="password"
				name="password"
				value=""
				autofocus
			/>
			</label>
			<br>
			<input type="submit" class="form-submit" value="Authorize" />
			<p class="notice"></p>
		</form>
		</body>`
