---
worth: later
where: README.md
added: 2026-11-25
---
# README multi-tenant section reads `aud` as proof of tenant membership

Every built-in login takes `aud` from the request (`site` or `aud` in oauth2, oauth1, Telegram and
verify, `creds.Audience` in the direct provider, whose `CredChecker` never sees it), so
`User.Audience` records which tenant the token was requested for, not that the user belongs to it.
The "Multi-tenant services" section promises that one customer's tokens cannot be used in another
customer's subsystem, and its line on per-tenant routes says only to compare `User.Audience` with the
tenant the request names. An application that does just that admits a user of tenant A on tenant B's
routes when the login accepts credentials shared across the service.

Fix: one clause in that section: `aud` comes from the login request, so the application also checks
that the authenticated user belongs to the tenant, at issuance (`ClaimsUpdater`) or on the route.
