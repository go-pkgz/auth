package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-pkgz/auth/token"
)

type contextKey string

// MustGetUserInfo fails if can't extract user data from the request.
// should be called from authenticated controllers only
func MustGetUserInfo(r *http.Request) token.User {
	user, err := GetUserInfo(r)
	if err != nil {
		panic(err)
	}
	return user
}

// GetUserInfo returns user from request context
func GetUserInfo(r *http.Request) (user token.User, err error) {

	ctx := r.Context()
	if ctx == nil {
		return token.User{}, errors.New("no info about user")
	}
	if u, ok := ctx.Value(contextKey("user")).(token.User); ok {
		return u, nil
	}

	return token.User{}, errors.New("user can't be parsed")
}

// SetUserInfo sets user into request context
func SetUserInfo(r *http.Request, user token.User) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, contextKey("user"), user)
	return r.WithContext(ctx)
}
