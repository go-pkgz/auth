---
worth: later
where: provider/oauth2.go:Oauth2Handler.AuthHandler
added: 2026-11-09
---
# oauth callback error logs keep the full query

Every error branch in the oauth2, oauth1 and Apple `AuthHandler` passes the original request to
`rest.SendErrorJSON`, which logs `r.URL.String()`. A failed callback therefore writes its query
parameters to the log: `code` and `state` for oauth2, `oauth_token` and `oauth_verifier` for oauth1,
and any value in the JWT query parameter (`token` by default). Apple's default `form_post` mode sends
`code` and `state` in the POST body, which is not logged; Apple callbacks with another response mode
carry them in the query. Same in `v2/provider/`. Since the cookie-only handshake fix, a cookieless callback carrying `?token=` is one of
the requests that fails and logs. Fix: pass a copy of the request with the query removed to the
callback's error logging in both modules, like `DirectHandler.scrubPasswordFromRequest`, plus a log
assertion in the callback tests. Deferred from the handshake fix to keep the hotfix small.
