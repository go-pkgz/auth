module github.com/go-pkgz/auth/_example

go 1.15

replace github.com/go-pkgz/auth => ../

require (
	github.com/go-chi/chi/v5 v5.0.3
	github.com/go-pkgz/auth v1.15.0
	github.com/go-pkgz/lgr v0.10.4
	github.com/go-pkgz/rest v1.11.0
	github.com/golang-jwt/jwt v3.2.1+incompatible
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	gopkg.in/oauth2.v3 v3.12.0
)
