---
worth: later
where: token/jwt.go:Opts
added: 2026-10-11
---
# turning PartitionedCookies off strands the partitioned cookie pair

`Set` and `Reset` expire the unpartitioned pair only when `PartitionedCookies` is on. Nothing expires the
partitioned pair when the option is later turned off. A browser that received a partitioned pair keeps it
next to the unpartitioned one, and `Reset` without the option cannot clear it: its expiry carries no
`Partitioned` attribute and does not match. Logout leaves a validly signed JWT that `Get` reads on the next
request, and a refresh does not stick, until `CookieDuration` runs out.

The godoc gives an operator a reason to turn the option off: it makes an OAuth session invisible to the
frame.

Agreed fix is one sentence in the `PartitionedCookies` godoc on `token.Opts` saying that disabling the
option leaves partitioned cookies in place until they expire. Same in `v2/token/jwt.go`.

Handling the off transition in code was considered and not chosen: always writing partitioned expiries
changes the headers for every deployment with the option off (`TestJWT_PartitionedCookiesOffByDefault`
pins two cookies and no `Partitioned`), and a partitioned expiry without `Secure` is dropped by the browser.

Surfaced reviewing https://github.com/go-pkgz/auth/pull/318.
