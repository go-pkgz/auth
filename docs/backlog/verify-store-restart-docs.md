---
worth: yes
where: README.md
added: 2026-11-25
---
# README and AGENTS.md call the in-memory verify store correct for a single instance

`AddVerifProvider` installs `NewInMemoryVerifStore` when `Opts.VerifConfirmationStore` is nil. The
store is a process-local map, so a restart forgets redeemed tokens, and a confirmation still inside
its 30-minute lifetime can be redeemed again on the same single instance. The godoc on
`Opts.VerifConfirmationStore` and `NewInMemoryVerifStore` says so in both modules; the README
("This is correct for **single-instance** deployments", section "Confirmation token replay
protection") and the AGENTS.md project rule on verify tokens still do not.

Fix: in the README add that a restart forgets redeemed tokens and a persistent
`Opts.VerifConfirmationStore` covers restarts; in AGENTS.md add "and forgotten on restart" to the
verify-token rule. Deferred until PR #341 is merged, since it rewrites the lines next to both.
