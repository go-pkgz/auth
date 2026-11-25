---
worth: later
where: provider/sender/email.go:EmailParams
added: 2026-11-25
---
# LoginAuth godoc still names outlook.com

The `EmailParams.LoginAuth` field comment in both modules says LOGIN is "needed for Office 365 and
outlook.com". Personal outlook.com mailboxes accept only OAuth2 for SMTP since September 2024, and
the sender has no OAuth2, so the README now describes `LoginAuth` as LOGIN for servers that offer
only LOGIN, e.g. Office 365 while the tenant allows basic SMTP auth. pkg.go.dev and the README
disagree.

Fix: match the README wording in `provider/sender/email.go` and `v2/provider/sender/email.go`.
