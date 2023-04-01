// Package main starts the example server
package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	goauth2 "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/rest/logger"
	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/middleware"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
)

func main() {

	log.Setup(log.Debug, log.Msec, log.LevelBraces, log.CallerFile, log.CallerFunc) // setup default logger with go-pkgz/lgr

	// define auth options
	options := auth.Opts{
		SecretReader: token.SecretFunc(func(_ string) (string, error) { // secret key for JWT, ignores aud
			return "secret", nil
		}),
		TokenDuration:     time.Minute,                                 // short token, refreshed automatically
		CookieDuration:    time.Hour * 24,                              // cookie fine to keep for long time
		DisableXSRF:       true,                                        // don't disable XSRF in real-life applications!
		Issuer:            "my-demo-service",                           // part of token, just informational
		URL:               "http://localhost:8080",                     // base url of the protected service
		AvatarStore:       avatar.NewLocalFS("/tmp/demo-auth-service"), // stores avatars locally
		AvatarResizeLimit: 200,                                         // resizes avatars to 200x200
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims { // modify issued token
			if claims.User != nil && claims.User.Name == "dev_admin" { // set attributes for dev_admin
				claims.User.SetAdmin(true)
				claims.User.SetStrAttr("custom-key", "some value")
			}
			return claims
		}),
		Validator: token.ValidatorFunc(func(_ string, claims token.Claims) bool { // rejects some tokens
			if claims.User != nil {
				if strings.HasPrefix(claims.User.ID, "github_") { // allow all users with github auth
					return true
				}
				if strings.HasPrefix(claims.User.ID, "microsoft_") { // allow all users with ms auth
					return true
				}
				if strings.HasPrefix(claims.User.ID, "patreon_") { // allow all users with ms auth
					return true
				}
				if strings.HasPrefix(claims.User.Name, "dev_") { // non-guthub allow only dev_* names
					return true
				}
				return strings.HasPrefix(claims.User.Name, "custom123_")
			}
			return false
		}),
		Logger:      log.Default(), // optional logger for auth library
		UseGravatar: true,          // for verified provider use gravatar service
	}

	// create auth service
	service := auth.NewService(options)
	service.AddProvider("dev", "", "")                                                             // add dev provider
	service.AddProvider("github", os.Getenv("AEXMPL_GITHUB_CID"), os.Getenv("AEXMPL_GITHUB_CSEC")) // add github provider
	service.AddProvider("twitter", os.Getenv("AEXMPL_TWITTER_APIKEY"), os.Getenv("AEXMPL_TWITTER_APISEC"))
	service.AddProvider("microsoft", os.Getenv("AEXMPL_MS_APIKEY"), os.Getenv("AEXMPL_MS_APISEC"))
	service.AddProvider("patreon", os.Getenv("AEXMPL_PATREON_CID"), os.Getenv("AEXMPL_PATREON_CSEC"))

	// allow sign with apple id
	appleCfg := provider.AppleConfig{
		ClientID:     os.Getenv("AEXMPL_APPLE_CID"),
		TeamID:       os.Getenv("AEXMPL_APPLE_TID"),
		KeyID:        os.Getenv("AEXMPL_APPLE_KEYID"), // private key identifier
		ResponseMode: "query",                         // see https://developer.apple.com/documentation/sign_in_with_apple/request_an_authorization_to_the_sign_in_with_apple_server?changes=_1_2#4066168
	}

	if err := service.AddAppleProvider(appleCfg, provider.LoadApplePrivateKeyFromFile(os.Getenv("AEXMPL_APPLE_PRIVKEY_PATH"))); err != nil {
		log.Printf("[ERROR] create AppleProvider failed: %v", err)
	}
	// allow anonymous user via custom (direct) provider
	service.AddDirectProvider("anonymous", anonymousAuthProvider())

	// add verified provider
	service.AddVerifProvider("email",
		"To confirm use {{.Token}}\nor follow http://localhost:8080/auth/email/login?token={{.Token}}",
		provider.SenderFunc(func(address string, text string) error { // sender just prints token
			fmt.Printf("CONFIRMATION for %s\n%s\n", address, text)
			return nil
		}),
	)

	if tkn := os.Getenv("TELEGRAM_TOKEN"); tkn != "" {
		// add telegram provider
		telegram := provider.TelegramHandler{
			ProviderName: "telegram",
			ErrorMsg:     "❌ Invalid auth request. Please try clicking link again.",
			SuccessMsg:   "✅ You have successfully authenticated!",
			Telegram:     provider.NewTelegramAPI(tkn, http.DefaultClient),

			L:            log.Default(),
			TokenService: service.TokenService(),
			AvatarSaver:  service.AvatarProxy(),
		}

		go func() {
			err := telegram.Run(context.Background())
			if err != nil {
				log.Fatalf("[PANIC] failed to start telegram: %v", err)
			}
		}()

		service.AddCustomHandler(&telegram)
	}

	// run dev/test oauth2 server on :8084
	go func() {
		devAuthServer, err := service.DevAuth() // peak dev oauth2 server
		if err != nil {
			log.Printf("[PANIC] failed to start dev oauth2 server, %v", err)
		}
		devAuthServer.Run(context.Background())
	}()

	// Example: start custom oauth2 server, add to handlers
	srv := initGoauth2Srv()
	sopts := provider.CustomServerOpt{
		URL:           "http://127.0.0.1:9096",
		L:             options.Logger,
		WithLoginPage: true,
	}
	// create custom provider and prepare params for handler
	prov := provider.NewCustomServer(srv, sopts)

	// Start server
	go prov.Run(context.Background())
	service.AddCustomProvider("custom123", auth.Client{Cid: "cid", Csecret: "csecret"}, prov.HandlerOpt)

	// Example: add different oauth2 provider
	c := auth.Client{
		Cid:     os.Getenv("AEXMPL_BITBUCKET_CID"),
		Csecret: os.Getenv("AEXMPL_BITBUCKET_CSEC"),
	}

	service.AddCustomProvider("bitbucket", c, provider.CustomHandlerOpt{
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://bitbucket.org/site/oauth2/authorize",
			TokenURL: "https://bitbucket.org/site/oauth2/access_token",
		},
		InfoURL: "https://api.bitbucket.org/2.0/user/",
		MapUserFn: func(data provider.UserData, _ []byte) token.User {
			userInfo := token.User{
				ID: "bitbucket_" + token.HashID(sha1.New(),
					data.Value("username")),
				Name: data.Value("nickname"),
			}
			return userInfo
		},
		Scopes: []string{"account"},
	})

	// retrieve auth middleware
	m := service.Middleware()

	// setup http server
	router := chi.NewRouter()
	// add some external middlewares from go-pkgz/rest
	router.Use(rest.AppInfo("auth-example", "umputun", "1.0.0"), rest.Ping)
	router.Use(logger.New(logger.Log(log.Default()), logger.WithBody, logger.Prefix("[INFO]")).Handler) // log all http requests
	router.Get("/open", openRouteHandler)                                                               // open page
	router.Group(func(r chi.Router) {
		r.Use(m.Auth)
		r.Use(m.UpdateUser(middleware.UserUpdFunc(func(user token.User) token.User {
			user.SetStrAttr("some_attribute", "attribute value")
			return user
		})))
		r.Get("/private_data", protectedDataHandler) // protected api
	})

	// static files under ~/web
	workDir, _ := os.Getwd()
	filesDir := filepath.Join(workDir, "frontend")
	fileServer(router, "/web", http.Dir(filesDir))

	// setup auth routes
	authRoutes, avaRoutes := service.Handlers()
	router.Mount("/auth", authRoutes)  // add auth handlers
	router.Mount("/avatar", avaRoutes) // add avatar handler

	httpServer := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           router,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		log.Printf("[PANIC] failed to start http server, %v", err)
	}
}

// anonymousAuthProvider allows auth-free login with any valid user name
func anonymousAuthProvider() provider.CredCheckerFunc {
	log.Printf("[WARN] anonymous access enabled")
	var isValidAnonName = regexp.MustCompile(`^[a-zA-Z][\w ]+$`).MatchString

	return func(user, _ string) (ok bool, err error) {
		user = strings.TrimSpace(user)
		if len(user) < 3 {
			log.Printf("[WARN] name %q is too short, should be at least 3 characters", user)
			return false, nil
		}

		if !isValidAnonName(user) {
			log.Printf("[WARN] name %q should have letters, digits, underscores and spaces only", user)
			return false, nil
		}
		return true, nil
	}
}

// FileServer conveniently sets up a http.FileServer handler to serve static files from a http.FileSystem.
// Borrowed from https://github.com/go-chi/chi/blob/master/_examples/fileserver/main.go
func fileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	log.Printf("[INFO] serving static files from %v", root)
	fs := http.StripPrefix(path, http.FileServer(root))

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}

// GET /open returns a page available without authorization
func openRouteHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("this is an open route, no token needed\n"))
}

// GET /private_data returns json with user info and ts
func protectedDataHandler(w http.ResponseWriter, r *http.Request) {

	userInfo, err := token.GetUserInfo(r)
	if err != nil {
		log.Printf("failed to get user info, %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	res := struct {
		TS     time.Time  `json:"ts"`
		Field1 string     `json:"fld1"`
		Field2 int        `json:"fld2"`
		User   token.User `json:"userInfo"`
	}{
		TS:     time.Now(),
		Field1: "some private thing",
		Field2: 42,
		User:   userInfo,
	}

	rest.RenderJSON(w, res)
}

// initialize go-oauth2/oauth2 server
func initGoauth2Srv() *goauth2.Server {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("custom", []byte("00000000"), jwt.SigningMethodHS512))

	// client memory store
	clientStore := store.NewClientStore()
	err := clientStore.Set("cid", &models.Client{
		ID:     "cid",
		Secret: "csecret",
		Domain: "http://localhost:8080",
	})
	if err != nil {
		log.Printf("failed to set up a client store for go-oauth2/oauth2 server, %s", err)
	}
	manager.MapClientStorage(clientStore)

	srv := goauth2.NewServer(goauth2.NewConfig(), manager)

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		if r.Form.Get("username") != "admin" || r.Form.Get("password") != "admin" {
			return "", fmt.Errorf("wrong creds. Use: admin admin")
		}
		return "custom123_admin", nil
	})

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Printf("Internal Error: %s", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Printf("Response Error: %s", re.Error.Error())
	})

	return srv
}
