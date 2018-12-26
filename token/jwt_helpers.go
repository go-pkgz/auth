package token

// Secret defines interface returning secret key for given id (aud)
type Secret interface {
	Get(id string) (string, error)
}

// SecretFunc type is an adapter to allow the use of ordinary functions as Secret. If f is a function
// with the appropriate signature, SecretFunc(f) is a Handler that calls f.
type SecretFunc func(id string) (string, error)

// Get calls f(id)
func (f SecretFunc) Get(id string) (string, error) {
	return f(id)
}

// ClaimsUpdater defines interface adding extras to claims
type ClaimsUpdater interface {
	Update(claims Claims) Claims
}

// ClaimsUpdFunc type is an adapter to allow the use of ordinary functions as ClaimsUpdater. If f is a function
// with the appropriate signature, ClaimsUpdFunc(f) is a Handler that calls f.
type ClaimsUpdFunc func(claims Claims) Claims

// Update calls f(id)
func (f ClaimsUpdFunc) Update(claims Claims) Claims {
	return f(claims)
}
