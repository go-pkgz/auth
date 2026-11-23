---
worth: later
where: v2/middleware/auth.go:Authenticator.auth
added: 2026-11-23
---
# a validator-rejected session keeps its cookie

When `Opts.Validator` rejects a token, or the provider is not allowed, `auth` calls `onError` first and
`JWTService.Reset` after it. With `Auth` the error response is already written, so the expiring
`Set-Cookie` headers are dropped and only reach the browser when an outer handler buffers the response,
as `http.TimeoutHandler` does. A blocked user keeps his JWT cookie: every protected route answers 401,
while `/auth/status` still says "logged in" and `/auth/user` still returns him. The refresh-failure
branch resets before writing and works. The same code is in the root `middleware/auth.go`.

Swapping the order is not enough. `token.Service.Get` reads `?token=` before the cookie, so an effective
reset would let an attacker's blocked token in a URL sign out whoever loads it. A fix has to reset only
when the rejected token came from the cookie, or ship together with dropping query tokens on these paths.
Raised by the review of PR #336; if its README section is merged, it describes this behaviour and has to
change with the fix.
