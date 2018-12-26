# auth - authentication via oauth2 [![Build Status](https://travis-ci.org/go-pkgz/auth.svg?branch=master)](https://travis-ci.org/go-pkgz/auth)

This library provides "social login" with Github, Google, Facebook and Yandex.  

- Multiple oauth2 providers can be used at the same time
- Special `dev` provider allows local testing and development
- JWT with secure cookie and XSRF headers
- Minimal scopes with user name, id and picture (avatar) only
- Integrated avatar proxy with FS, boltdb or gridfs storage
- Support of user-defined storages
- Black list with user-defined validator
- Multiple aud (audience) supported
- Secure key with customizable `SecretReader`
- Ability to store extra information to token and retrieve on login
- Middleware for easy integration into http routers

## install

`go install github.com/go-pkgz/auth`

## usage

Example with chi router:

```go
func main() {
	/// define options
	options := auth.Opts{
		SecretReader:   token.SecretFunc(func(id string) (string, error) { return "secret", nil }),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-test-app",
		URL:            "http://127.0.0.1:8080",
		AvatarStore:    avatar.NewLocalFS("/tmp", 120),
	}

	// create auth service
	service, err := auth.NewService(options)
	if err != nil {
		log.Fatal(err)
	}
	service.AddProvider("github", "<Client ID>", "<Client Secret>")   // add github provider
	service.AddProvider("facebook", "<Client ID>", "<Client Secret>") // add facebook provider

	// retrieve auth middleware
	m := service.Middleware()

	// setup http server
	router := chi.NewRouter()
	router.Get("/open", openRouteHandler)                            // open api
	router.With(m.Auth(true)).Get("/private", protectedRouteHandler) // protected api

	// setup auth routes
	authRoutes, avaRoutes := service.Handlers()
	router.Mount("/auth", authRoutes)  // add token handlers
	router.Mount("/avatar", avaRoutes) // add avatar handler

	log.Fatal(http.ListenAndServe(":8080", router))
}
```



