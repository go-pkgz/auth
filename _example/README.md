# go-pkgz/auth example

## build and try

- run `go run main.go`
- open route: http://localhost:8080/open
- web application - http://localhost:8080/web

## parameters

No command line parameters needed. Each provider below is enabled by its environment variables:

| Provider  | Environment variables                                                                         |
|-----------|-----------------------------------------------------------------------------------------------|
| github    | `AEXMPL_GITHUB_CID`, `AEXMPL_GITHUB_CSEC`                                                     |
| twitter   | `AEXMPL_TWITTER_APIKEY`, `AEXMPL_TWITTER_APISEC`                                              |
| microsoft | `AEXMPL_MS_APIKEY`, `AEXMPL_MS_APISEC`                                                        |
| patreon   | `AEXMPL_PATREON_CID`, `AEXMPL_PATREON_CSEC`                                                   |
| discord   | `AEXMPL_DISCORD_CID`, `AEXMPL_DISCORD_CSEC`                                                   |
| apple     | `AEXMPL_APPLE_CID`, `AEXMPL_APPLE_TID`, `AEXMPL_APPLE_KEYID`, `AEXMPL_APPLE_PRIVKEY_PATH`     |
| bitbucket | `AEXMPL_BITBUCKET_CID`, `AEXMPL_BITBUCKET_CSEC`                                               |
| telegram  | `TELEGRAM_TOKEN` (bot token; the provider is registered only when it is set)                  |

`dev` (a fake oauth2 server on :8084) and `custom123` (a local go-oauth2 server on 127.0.0.1:9096, log in as `admin` with password `admin`) work without any variables, and so do `anonymous` and `email`, which prints the confirmation to stdout. Dev users reach `/private_data` with a name starting with `dev_`.

_see https://github.com/go-pkgz/auth#github-auth-provider_
