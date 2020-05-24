package middleware

import (
	"github.com/go-pkgz/auth/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUserUpdate(t *testing.T) {
	a := makeTestAuth(t)
	mux := http.NewServeMux()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, err := token.GetUserInfo(r)
		require.NoError(t, err)
		assert.Equal(t, "testValue", userInfo.StrAttr("testAttr"))

		w.WriteHeader(201)
	})
	upd := UserUpdFunc(func(user token.User) token.User {
		user.SetStrAttr("testAttr", "testValue")
		return user
	})
	updateUserHandler := a.UpdateUser(upd)(handler)
	mux.Handle("/trace", a.Trace(updateUserHandler))

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	// check everything works if there is no Trace/Auth/AdminOnly middleware
	req, err := http.NewRequest("GET", server.URL+"/trace", nil)
	require.NoError(t, err)
	req.Header.Add("X-JWT", testJwtValid)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "trace with userUpdate")

}

func TestUserUpdate_WithoutAuth(t *testing.T) {
	a := makeTestAuth(t)
	mux := http.NewServeMux()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	})
	upd := UserUpdFunc(func(user token.User) token.User {
		// this method should not be called because there is no user info in request context
		assert.True(t, false)
		return user
	})
	updateUserHandler := a.UpdateUser(upd)(handler)
	mux.Handle("/no_auth", updateUserHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	// check everything works if there is no Trace/Auth/AdminOnly middleware
	req, err := http.NewRequest("GET", server.URL+"/no_auth", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode, "no auth")
}
