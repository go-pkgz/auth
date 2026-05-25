# Project Guidance

## Commands

| Command | Purpose |
|---------|---------|
| `go test -p 1 ./...` | Run the root `github.com/go-pkgz/auth` module tests. |
| `cd v2 && go test -p 1 ./...` | Run the `github.com/go-pkgz/auth/v2` module tests. |
| `go test -timeout=60s -v -race -p 1 -covermode=atomic -coverprofile=$GITHUB_WORKSPACE/profile.cov ./...` | Root-module CI test command from `.github/workflows/ci.yml`. |
| `cd v2 && go test -timeout=60s -v -race -p 1 -covermode=atomic -coverprofile=$GITHUB_WORKSPACE/profile.cov ./...` | v2-module CI test command from `.github/workflows/ci-v2.yml`. |
| `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2 run --max-issues-per-linter=0 --max-same-issues=0` | Reproduce root-module CI lint locally. |
| `cd v2 && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2 run --config ../.golangci.yml --max-issues-per-linter=0 --max-same-issues=0` | Reproduce v2-module CI lint locally. |
| `~/.claude/format.sh` | Format Go code when available; it runs gofmt/goimports. |

## Architecture

- root module `github.com/go-pkgz/auth` is the v1 API; `v2/` is a separate Go module `github.com/go-pkgz/auth/v2` with mirrored packages.
- `_example/` is a separate example module that replaces `github.com/go-pkgz/auth/v2 => ../v2`; v2 CI builds it before testing `v2/`.
- `auth.go` wires the public `Service`, providers, middleware, token service, avatar proxy, and security headers.
- `provider/` contains OAuth1/OAuth2, Apple, direct, verify, Telegram, dev, and custom-provider flows; most provider changes need the same change under `v2/provider/`.
- `token/` wraps JWT/cookie/XSRF behavior; v1 uses `github.com/golang-jwt/jwt` v3 claims, v2 uses `github.com/golang-jwt/jwt/v5` registered claims.
- `avatar/` owns avatar proxying/storage and has filesystem, bbolt, GridFS, and no-op stores.
- `middleware/` owns auth, trace, admin-only, RBAC, basic auth, validator, token refresh, and request user context.

## CI and Lint Notes

- CI pins golangci-lint through GitHub Actions (`golangci/golangci-lint-action@v7` with `version: v2.6.2` in `.github/workflows/ci*.yml`). Newer local `golangci-lint` versions can report extra `gosec` findings that CI does not enforce.
- Root CI (`.github/workflows/ci.yml`) ignores `v2/**`, `_example/**`, and `ci-v2.yml`; v2 CI (`.github/workflows/ci-v2.yml`) runs only for `v2/**`, `_example/**`, and `ci-v2.yml` changes.
- Mongo-backed tests run in CI with `ENABLE_MONGO_TESTS=true` after `wbari/start-mongoDB@v0.2` starts MongoDB 6.0.
- The workflow coverage step currently installs `github.com/mattn/goveralls@latest` with `COVERALLS_TOKEN=${{ secrets.GITHUB_TOKEN }}`; security reviews should keep checking this supply-chain path.

## Project Rules

- For behavior shared by v1 and v2, update root and `v2/` implementations and tests together unless the difference is explicitly version-specific.
- Preserve backward compatibility for public auth flows and documented query parameters. For example, direct login still supports `passwd` in the URL, so sensitive-query fixes must redact rather than remove that input path.
- Avoid logging raw user profiles, mapped `token.User` values, JWTs, OAuth tokens, confirmation tokens, or credential-bearing URLs. Use redacted request copies when passing URLs with secrets to `rest.SendErrorJSON`.
- `AllowedRedirectHosts` hardening is opt-in. Nil keeps legacy permissive `from` redirects; a non-nil getter enables host validation.
- Verify-provider confirmation tokens are one-shot only when `VerifConfirmationStore` is configured; nil installs an in-memory store via `AddVerifProvider`, suitable only for single-instance deployments.
- Avatar handling is security-sensitive: keep content-type validation, image dimension/size caps, and bot-token URL redaction intact in both root and v2.

## Testing Gotchas

- Run root and v2 tests separately; `go test ./...` from the root does not test the separate `v2` module.
- When reproducing CI lint, use the pinned `v2.6.2` command above, not the globally installed `golangci-lint` binary unless its version matches CI.
- Many tests bind fixed localhost ports in the 898x/899x range; use `-p 1` for package test runs to reduce port-collision risk.
- `go test ./...` in the root includes Mongo tests only when `ENABLE_MONGO_TESTS=true`; without it, CI-only Mongo coverage may not run locally.
