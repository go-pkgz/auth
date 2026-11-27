---
worth: later
where: provider/oauth2.go:makeRedirURL
added: 2026-11-27
---
# README does not say callbacks need the mount in the handler's path

The oauth2, oauth1 and Apple providers build the callback URL from `Opts.URL` plus the login path as the
handler sees it (`makeRedirURL` in provider/oauth2.go, provider/oauth1.go and provider/apple.go, the same
in v2). An app that mounts the handler under `http.StripPrefix("/auth", h)` with the origin-only
`Opts.URL` the README shows sends users to `<origin>/github/callback`, outside the mount. Putting the
prefix into `Opts.URL` instead moves avatar links, turns the dev provider's hardcoded
`p.URL + "/auth/dev/callback"` (provider/dev_provider.go:NewDev) into `/auth/auth/dev/callback`, and
breaks email links from templates that already append `/auth`, as the README example does. Under
`Opts.AuthRoutePath` those extra elements get 404.

Fix: a README sentence saying the auth handler must keep its own mount element in the path it sees, and
that a prefix a parent router strips has to be in `Opts.URL` with the avatar route under it. The dev
provider's "mounted at /auth" note stays. Surfaced reviewing PR #346, which tests `AuthRoutePath: "/"`
under `StripPrefix` with the direct provider only.
