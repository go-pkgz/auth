---
worth: yes
where: provider/oauth2.go:Oauth2Handler.AuthHandler
added: 2026-10-26
---
# oauth2 user info unmarshal error is missing from the log

When the user info body is not valid JSON, `AuthHandler` binds the parse error to `e` but passes `err`
to `rest.SendErrorJSON`. `err` is the earlier `io.ReadAll` result and is nil there, so the logged error
details show no cause for the failure. The same line is in `v2/provider/oauth2.go`. Fix is `err` -> `e`
in both modules plus a test that feeds a non-JSON 200 body. Found while reviewing discussion #112.
