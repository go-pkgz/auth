---
worth: later
where: auth.go:AddProviderWithUserAttributes
added: 2026-11-01
---
# README does not document AddProviderWithUserAttributes

`AddProviderWithUserAttributes` maps extra fields of a built-in provider's user info response into
`token.User` attributes (key is the provider field, value is the attribute name, set with
`SetStrAttr`), but the README never describes it. Readers find it only from code, and the README
mentions it once, in "Google user email", to say it cannot supply email. A short paragraph under
"User info" or "Customization" with one mapping example would cover it. It only returns fields the
built-in provider's scopes already allow, which is the limit that section explains for Google.
