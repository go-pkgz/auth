module github.com/go-pkgz/auth/_example

replace github.com/go-pkgz/auth => ../

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-chi/chi v4.1.1+incompatible
	github.com/go-pkgz/auth v0.4.1
	github.com/go-pkgz/lgr v0.7.0
	github.com/go-pkgz/rest v1.5.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	gopkg.in/oauth2.v3 v3.12.0
)

go 1.13
