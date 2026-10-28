---
worth: later
where: provider/providers.go:NewGoogle
added: 2026-10-28
---
# README does not say the built-in Google provider cannot return the user's email

`NewGoogle` requests only the `userinfo.profile` scope, and Google returns `email` only when the email
scope was requested. So `AddProviderWithUserAttributes("google", ..., {"email": "email"})` maps an empty
value, and the README documents neither the gap nor `AddProviderWithUserAttributes` itself. The working
path is `AddCustomProvider` with `google.Endpoint`, the v3 userinfo URL, `Scopes` including email, and a
`MapUserFn` that hashes `sub` the way `NewGoogle` does. Users hit this in
https://github.com/go-pkgz/auth/discussions/180 and https://github.com/go-pkgz/auth/issues/268. The minimal
scope is deliberate (https://github.com/go-pkgz/auth/issues/37), so the fix is a README note with a short
example under "Custom oauth2" or the Google section of "Register oauth2 providers", not a scope change.
