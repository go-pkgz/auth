module github.com/go-pkgz/auth/_example

go 1.15

replace github.com/go-pkgz/auth => ../

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-chi/chi/v5 v5.0.3
	github.com/go-pkgz/auth v1.15.0
	github.com/go-pkgz/lgr v0.10.4
	github.com/go-pkgz/rest v1.9.2
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	gopkg.in/oauth2.v3 v3.12.0
)
