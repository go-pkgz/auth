package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-pkgz/auth/provider"
	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/rest/logger"

	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/token"
)

func main() {

	log.Setup(log.Debug, log.Msec, log.LevelBraces, log.CallerFile, log.CallerFunc) // setup default logger with go-pkgz/lgr

	/// define auth options
	options := auth.Opts{
		SecretReader: token.SecretFunc(func() (string, error) { // secret key for JWT
			return "secret", nil
		}),
		TokenDuration:  time.Minute,    // short token, refreshed automatically
		CookieDuration: time.Hour * 24, // cookie fine to keep for long time
		// DisableXSRF:       true,                                     // don't disable XSRF in real-life applications!
		Issuer:            "my-demo-service",                           // part of token, just informational
		URL:               "http://127.0.0.1:8080",                     // base url of the protected service
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
				return strings.HasPrefix(claims.User.Name, "dev_") // non-guthub allow only dev_* names
			}
			return false
		}),
		Logger: log.Default(), // optional logger for auth library
	}

	// create auth service
	service := auth.NewService(options)
	service.AddProvider("dev", "", "")                                                             // add dev provider
	service.AddProvider("github", os.Getenv("AEXMPL_GITHUB_CID"), os.Getenv("AEXMPL_GITHUB_CSEC")) // add github provider

	// allow anonymous user via custom (direct) provider
	service.AddDirectProvider("anonymous", anonymousAuthProvider())

	// run dev/test oauth2 server on :8084
	go func() {
		devAuthServer, err := service.DevAuth() // peak dev oauth2 server
		if err != nil {
			log.Printf("[PANIC] failed to start dev oauth2 server, %v", err)
		}
		devAuthServer.Run(context.Background())
	}()

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

	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Printf("[PANIC] failed to start http server, %v", err)
	}
}

// anonymousAuthProvider allows auth-free login with any valid user name
func anonymousAuthProvider() provider.CredCheckerFunc {
	log.Printf("[WARN] anonymous access enabled")
	var isValidAnonName = regexp.MustCompile(`^[a-zA-Z][\w ]+$`).MatchString

	return provider.CredCheckerFunc(func(user, _ string) (ok bool, err error) {
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
	})
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
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

// GET /open returns a page available without authorization
func openRouteHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("this is an open route, no token needed\n"))
}

// GET /private_data returns json with user info and ts
func protectedDataHandler(w http.ResponseWriter, r *http.Request) {

	res := struct {
		TS     time.Time `json:"ts"`
		Field1 string    `json:"fld1"`
		Field2 int       `json:"fld2"`
	}{
		TS:     time.Now(),
		Field1: "some private thing",
		Field2: 42,
	}

	rest.RenderJSON(w, r, res)
}
