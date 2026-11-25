---
worth: yes
where: README.md
added: 2026-11-25
---
# README does not say a self-built handler must set claims.ID for the XSRF check

`token.Service.Set` writes `claims.ID` into the XSRF cookie, and `Get` compares the
`X-XSRF-TOKEN` header with `claims.ID` for a cookie token. Every built-in provider sets a random ID,
but `Set` does not fill an empty one, so a self-built login handler that issues the user cookie
through `Set` with an empty ID gets an XSRF check that passes with no header (`"" == ""`). The
"Self-implemented auth handler" section never says how a handler issues a user cookie.

Fix: one sentence in that section: a handler issuing a user cookie through `Set` sets a random,
non-empty `claims.ID`, as the built-in providers do.
