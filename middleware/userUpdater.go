package middleware

import (
	"github.com/go-pkgz/auth/token"
	"net/http"
)

// UserUpdater defines interface adding extras or modifying UserInfo in request context
type UserUpdater interface {
	Update(claims token.User) token.User
}

// UserUpdFunc type is an adapter to allow the use of ordinary functions as UserUpdater. If f is a function
// with the appropriate signature, UserUpdFunc(f) is a Handler that calls f.
type UserUpdFunc func(user token.User) token.User

// Update calls f(user)
func (f UserUpdFunc) Update(user token.User) token.User {
	return f(user)
}

// UpdateUser update user info with UserUpdater if it exists in request's context. Otherwise do nothing.
// should be places after either Auth, Trace or AdminOnly middleware.
func (a *Authenticator) UpdateUser(upd UserUpdater) func(http.Handler) http.Handler {
	f := func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			user, err := token.GetUserInfo(r)
			if err == nil {
				r = token.SetUserInfo(r, upd.Update(user))
			}

			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
	return f
}