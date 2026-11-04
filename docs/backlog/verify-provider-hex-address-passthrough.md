---
worth: maybe
where: provider/verify.go:VerifyHandler.LoginHandler
added: 2026-10-27
---
# verify provider id passes a 40-hex address through unhashed

`VerifyHandler` builds the user id as `ProviderName + "_" + token.HashID(sha1.New(), address)`, and
`HashID` returns any 40-char hex input unchanged. An address equal to the sha1 of another user's
address would get that user's id. Email cannot hit it (no `@`), so it matters only for a Sender
whose address namespace accepts arbitrary 40-hex strings, and the attacker must still receive the
confirmation there. The direct provider avoids this by hashing the username with plain sha1; the
same change here would give new ids to existing 40-hex addresses. Same code in
`v2/provider/verify.go`.
