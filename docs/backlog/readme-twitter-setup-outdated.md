---
worth: later
where: README.md
added: 2026-10-23
---
# README still advertises Twitter login with setup steps that no longer work for new apps

The README lists Twitter among supported providers in its opening line and gives setup steps under
"Twitter Auth Provider". Neither mentions that `NewTwitter` uses OAuth1 against the v1.1
`verify_credentials` endpoint, which new X developer apps cannot reach without elevated or paid access,
so following the steps produces a login that fails or returns a blank user. remark42 deprecated Twitter
auth in 1.14.0 (https://github.com/umputun/remark42/pull/1828) and removed its examples in
https://github.com/umputun/remark42/pull/2147. paskal asked for this README update in
https://github.com/go-pkgz/auth/issues/111, which was closed as stale. Fix is a note on the access
requirement, or dropping Twitter from the advertised list while keeping the provider.
