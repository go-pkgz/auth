# go-pkgz/auth example

## build and try

- run `go run main.go`
- open route: http://localhost:8080/open
- web application - http://localhost:8080/web

## parameters

No command line parameters needed. To enable github provider define two env variables:

- `AEXMPL_GITHUB_CID` - github client id
- `AEXMPL_GITHUB_CSEC` - github client secret

_see https://github.com/go-pkgz/auth#github-auth-provider_