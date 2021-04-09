package token

// BasicAuth defines interface to check credentials in store
type BasicAuth interface {
	Check(user, passwd string) (ok bool, userInfo User, err error)
}

// BasicAuthFunc type is an adapter to allow the use of ordinary functions as BasicAuth.
type BasicAuthFunc func(user, passwd string) (ok bool, userInfo User, err error)

// Check calls f(user,password). Second parameter need for pass user claims to request context
// and check one in RBAC middleware if it's used
func (f BasicAuthFunc) Check(user, passwd string) (bool, User, error) {
	return f(user, passwd)
}
