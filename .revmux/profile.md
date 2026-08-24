# Project profile: go-pkgz/auth

## What it is

A public Go library providing authentication for other people's services: OAuth2 and OAuth1 social login
across a dozen providers, direct credential auth, email/IM verification, JWT in a secure cookie with XSRF
protection, an avatar proxy with several storage backends, and middleware for auth, RBAC and admin-only
routes. Its best-known consumer is remark42, but it is imported broadly and nothing tells us who else
depends on any given behavior.

Two live major versions in one repository. The root module is `github.com/go-pkgz/auth` (v1); `v2/` is a
separate module `github.com/go-pkgz/auth/v2` with mirrored packages, on jwt/v5 where v1 is on jwt v3.
`_example/` is a third module that replaces v2 with the local copy.

## Backward compatibility is the first thing to check

This library is deployed in production by people we never hear from, who upgrade on their own schedule
and cannot be asked to change their code. Project policy is that a confirmed break is **critical**,
because downstream usage is unknown and a published contract cannot be recalled once a version is tagged.

That is a floor on how a break is rated, not a ranking against other defects. Security defects are rated
on their own impact and a serious one outranks a break: an authentication bypass or a token-validation
flaw can affect every request, where a removed niche API affects only the callers that used it. Never
downgrade a security finding to make room for a compatibility one.

Check every change for the following, and report what you find as **critical**:

- a public function, method, type, struct field or constant removed, renamed, or given a different
  signature, including a new parameter or a new return value
- an exported struct gaining a required field, or a `Params`/`Opts` field changing meaning
- a default changing, so an existing caller that passes nothing now gets different behavior
- a cookie attribute, header, claim, route or query parameter that existing clients or already-issued
  tokens depend on, changing shape or disappearing
- a user id derivation changing, which silently orphans every stored record keyed on it
- an error, a status code or a redirect target that callers branch on, changing

A behavior added to one module and not the other is a different thing and does not belong on that list:
it breaks nobody's existing code, it is a mirroring defect and a v1-to-v2 migration inconsistency. Report
it under the mirroring rule below, on its own impact, not as a compatibility break.

A change that is only additive, keeps existing defaults, and leaves every existing call compiling and
behaving as before is compatible. Say so plainly when that is what the diff is; it is a real answer and
it is the common case.

## What a real failure looks like here

- An authentication bypass, or a token accepted that should not be.
- Two distinct people resolving to the same user id, so one inherits the other's records, roles and blocks.
- Credentials reaching somewhere they should not: a client secret sent to the wrong host, a token or a
  credential-bearing URL written to a log, or a session cookie readable by page script because `HttpOnly`
  was dropped.
- Cookie attributes failing in their own distinct ways, which must not be conflated. `HttpOnly` alone
  governs whether page script can read the cookie. `Secure` governs whether it travels in cleartext.
  `SameSite` and `Partitioned` govern where the cookie is stored and when the browser attaches it, so a
  wrong value there shows up as a session that fails cross-site, a cookie attached where it should not
  be, or changed CSRF exposure — never as script readability. Report the failure the attribute actually
  causes.
- A login flow that breaks for every downstream service on upgrade, or a public API change that cannot be
  walked back once tagged.
- A behavior present in v1 and missing in v2, or the reverse, where the two were supposed to match.

## Blast radius

Every service that imports the library, on their schedule rather than ours. An auth defect is a security
defect. A published API shape is effectively irreversible once tagged, and so is any change to how a user
id is derived, since downstream records are keyed on it. Nothing here is recoverable by a redeploy.

## Reporting bar

High for correctness, compatibility and anything touching credentials, identity derivation, cookie
attributes or redirect validation. Report those even when the trigger needs an operator mistake, because
the operator is a third party we never hear from.

Lower for style. The project pins its own linters (`.golangci.yml`, golangci-lint v2.12.2 in CI) and a
formatter; findings a configured tool already owns are noise. Line length is 140, not 120.

A finding must name an observable symptom and a trigger that actually occurs. An untested branch with no
defect behind it, or two code paths differing with nothing visible differing, is not a finding.

## Conventions that are deliberate, not defects

- **v1/v2 mirroring is a rule, not duplication.** Behavior shared by both modules changes in both,
  implementation and tests together, unless the difference is genuinely version-specific. Flag a change
  that lands in only one of them; do not flag the duplication itself.
- **Backward compatibility is preserved even when it looks wrong.** Direct login still accepts `passwd`
  in the URL. Sensitive-query fixes redact that input path rather than removing it. Proposing removal of a
  documented parameter is a finding about the proposal, not about the code.
- **`AllowedRedirectHosts` hardening is opt-in by design.** Nil keeps the legacy permissive `from`
  redirect; a non-nil getter turns host validation on. Nil is not a missing check.
- **Verify-provider confirmation tokens are one-shot only when `VerifConfirmationStore` is set.** Nil
  installs an in-memory store through `AddVerifProvider`, which is documented as single-instance only.
- **Avatar handling is security-sensitive and its guards are load-bearing**: content-type validation,
  image dimension and size caps, bot-token URL redaction. Removing or weakening any of them in either
  module is a finding.
- **Never log raw user profiles, mapped `token.User` values, JWTs, OAuth tokens, confirmation tokens, or
  credential-bearing URLs.** Redacted request copies go to `rest.SendErrorJSON`.
- Provider constructors take a `Params` struct and return a value, not an error. Provider-specific fields
  on that shared struct (`MicrosoftTenant`, `GithubNumericID`) are the established pattern.

## Testing notes

Root and v2 are tested separately; `go test ./...` from the root does not reach the v2 module. Many tests
bind fixed localhost ports in the 898x/899x range, so package runs use `-p 1`. Mongo-backed tests run only
with `ENABLE_MONGO_TESTS=true`, so a local run skipping them is expected and not a failure.

## Authorship

Most changes come from the maintainer (umputun) or from paskal, a regular contributor with commit history
across these repositories. A published PR from either carries implicit design approval: do not re-argue
whether the change should exist or propose a preferred alternative design. That does not lower the
correctness or compatibility bar, which stays exactly where the sections above put it.
