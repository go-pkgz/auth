module github.com/go-pkgz/auth/_example

replace github.com/go-pkgz/auth => ../

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-pkgz/auth v0.4.1
	github.com/go-pkgz/lgr v0.6.2
	github.com/go-pkgz/rest v1.4.1
	gopkg.in/oauth2.v3 v3.10.1
)
