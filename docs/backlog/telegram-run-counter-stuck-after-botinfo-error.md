---
worth: later
where: provider/telegram.go:TelegramHandler.Run
added: 2026-11-27
---
# Telegram Run keeps its running mark after a BotInfo error

`Run` increments `th.run` before calling `BotInfo` and returns on a `BotInfo` error without
decrementing it; only the `ctx.Done` branch does `th.run.Add(-1)`. After that error the handler still
counts as running, so `ProcessUpdate` refuses every later call with "Run goroutine should not be used
with ProcessUpdate", even though no `Run` loop exists. A caller that falls back to `ProcessUpdate` once
`Run` fails is stuck. Same code in `v2/provider/telegram.go`. Surfaced by the revmux round on the
coveralls-v2-only branch. The fix is a deferred decrement plus a test that fails `BotInfo` and then calls
`ProcessUpdate`. Moving the increment after `BotInfo` would not do: `ProcessUpdate` could then run
during initialization, while `Run` resets the request map.
