---
worth: yes
where: v2/middleware/auth.go:refreshExpiredToken
added: 2026-10-23
---
# token refresh logs the whole token.User at DEBUG

`refreshExpiredToken` logs `[DEBUG] token refreshed for %+v` with `claims.User`, in both
`middleware/auth.go` and `v2/middleware/auth.go`. That prints the full mapped user, including every
attribute, which goes against the AGENTS.md rule not to log mapped `token.User` values. Any provider
attribute a consumer maps in (email, raw provider fields via `UserAttributes`) ends up in debug logs on
every refresh. Fix: log the user ID only, in both modules.
