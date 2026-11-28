---
worth: later
where: provider/telegram_test.go:setupHandler
added: 2026-11-27
---
# Telegram test setup can leave Run running when its init wait times out

`setupHandler` starts `tg.Run` in a goroutine, then waits with `require.Eventually` for "Run did not
initialize". If that wait times out, `require` stops the test before the cleanup func that cancels the
context and waits for `Run` is returned, so cancel and join are skipped and `Run` can be left running
for the rest of the package's tests: blocked in `BotInfo`, or polling the mock. When `BotInfo` already
returned an error, `Run` has exited and nothing leaks. No run has hit the timeout so far. Same helper in `v2/provider/telegram_test.go`.
Surfaced by the revmux round on the coveralls-v2-only branch; the fix is registering the cancel and join
with `t.Cleanup` inside `setupHandler` before the wait.
