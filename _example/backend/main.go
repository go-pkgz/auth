package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"

	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/rest/logger"

	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
)

func main() {

	/// define options
	options := auth.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { // secret key for JWT
			return "secret", nil
		}),
		TokenDuration:     time.Minute,                                 // short token, refreshed automatically
		CookieDuration:    time.Hour * 24,                              // cookie fine to keep for long time
		DisableXSRF:       true,                                        // don't do this in real-life applications!
		Issuer:            "my-demo-service",                           // part of token, just informational
		URL:               "http://127.0.0.1:8080",                     // base url of the protected service
		AvatarStore:       avatar.NewLocalFS("/tmp/demo-auth-service"), // stores avatars locally
		AvatarResizeLimit: 200,                                         // resizes avatars to 200x20
		ClaimsUpd: token.ClaimsUpdFunc(func(claims token.Claims) token.Claims { // modify issued token
			if claims.User != nil && claims.User.Name == "dev_admin" { // set attributes for dev_admin
				claims.User.SetAdmin(true)
				claims.User.SetStrAttr("custom-key", "some value")
			}
			return claims
		}),
		Validator: token.ValidatorFunc(func(_ string, claims token.Claims) bool { // rejects some tokens
			return claims.User != nil && strings.HasPrefix(claims.User.Name, "dev_") // allow only dev_* names
		}),
	}

	// create auth service
	service := auth.NewService(options)
	service.AddProvider("dev", "", "")                                                             // add dev provider
	service.AddProvider("github", os.Getenv("AEXMPL_GITHUB_CID"), os.Getenv("AEXMPL_GITHUB_CSEC")) // add github provider

	// run dev/test oauth2 server on :8084
	go func() {
		p, err := service.Provider("dev") // peak dev provider
		if err != nil {
			log.Fatal(err)
		}
		// make and start dev auth server
		devAuthServer := provider.DevAuthServer{Provider: p}
		devAuthServer.Run()
	}()

	// retrieve auth middleware
	m := service.Middleware()

	// setup http server
	router := chi.NewRouter()
	router.Use(rest.AppInfo("auth-example", "umputun", "1.0.0"), rest.Ping) // add some external middlewares from go-pkgz/rest
	router.Use(logger.Logger)                                               // log all http requests
	router.Get("/open", openRouteHandler)                                   // open page
	router.Group(func(r chi.Router) {
		r.Use(m.Auth)
		r.Get("/private", protectedPageHandler)      // protected page
		r.Get("/private_data", protectedDataHandler) // protected api
	})

	// setup auth routes
	authRoutes, avaRoutes := service.Handlers()
	router.Mount("/auth", authRoutes)  // add auth handlers
	router.Mount("/avatar", avaRoutes) // add avatar handler

	log.Fatal(http.ListenAndServe(":8080", router))
}

// GET /open
func openRouteHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("this is an open route, no token needed\n"))
}

// GET /private returns complete page for authenticated users only
func protectedPageHandler(w http.ResponseWriter, r *http.Request) {
	u := token.MustGetUserInfo(r)
	b, err := json.MarshalIndent(u, "", "    ")
	if err != nil {
		rest.SendErrorJSON(w, r, 500, err, "can't parse user info")
	}
	p := fmt.Sprintf(page, string(b), u.Picture)
	_, _ = w.Write([]byte(p))
}

// GET /private_data returns json with user info and ts
func protectedDataHandler(w http.ResponseWriter, r *http.Request) {

	u, err := token.GetUserInfo(r)
	if err != nil {
		rest.SendErrorJSON(w, r, http.StatusInternalServerError, err, "something wrong")
		return
	}

	res := struct {
		TS       time.Time `json:"ts"`
		UserName string    `json:"user_name"`
		Picture  string    `json:"picture"`
	}{
		TS:       time.Now(),
		UserName: u.Name,
		Picture:  u.Picture,
	}

	rest.RenderJSON(w, r, res)
}

var page = `
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>go-pkgz/auth, protected page</title>
  <style>
		body {
			margin: 0;
			padding: 20px;
			text-align: center;
			font: 18px/24px Helvetica, Arial, sans-serif;
			color: #333;
		}

		@media (min-width: 768px) {
			body {
				padding: 150px;
			}
		}

		article {
			display: block;
			text-align: left;
			max-width: 640px;
			margin: 0 auto;
		}
		pre {
			font-size: 0.8em;
			margin: 5px;
			color: #833;
		}
		h1 {
			font-size: 50px;
			margin-left: -0.05em;
		}

		ul {
			color: rgb(23, 67, 78);
		}

		a {
			color: rgb(79, 187, 214);
			text-decoration: none;
		}

		a:hover {
			color: rgb(94, 167, 177);
			text-decoration: underline;
		}
		</style>
</head>

<body>
  <article>
    <h1>protected page</h1>
    <div>
      <p>This page available to authorized users only!</p>
	  
	  <p>user details: <pre>%+v</pre></p>
	  <p><img src="%s"/></p>
	  <p><a href="https://github.com/go-pkgz/auth">source on github</a></p>
      <p>&mdash; Umputun</p>
    </div>
  </article>
</body>

</html>
`
