---
worth: yes
where: README.md
added: 2026-10-23
---
# dev provider docs omit that the browser host must match Opts.URL

The dev OAuth server sends the browser back to `Opts.URL + "/auth/dev/callback"`. When the app is
opened on a different host than `Opts.URL` names (`localhost` vs `127.0.0.1`), the handshake cookie
was set on the other host, so the callback fails with `failed to get token - token cookie was not
presented`. The README "Dev provider" section does not say this, and the error reads like a SameSite
or port problem. Issue #259 attributed it to the separate dev port; cross-port login works in
Chromium with SameSite unset, Lax and Strict, and only the host mismatch reproduces the error.

Fix: one sentence in the README dev provider section (root only, v2 shares the README).
