package provider

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/generates"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

func TestCustomProvider(t *testing.T) {
	srv := initCustomProvider()

	params := Params{
		URL: "http://127.0.0.1:8080",
		JwtService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
			DisableIAT:     true,
		}),
		Issuer:  "test-issuer",
		Cid:     "cid",
		Csecret: "csecret",
		L:       logger.Std,
	}

	h := NewCustHandler(params)
	s := Service{Provider: h}

	d, err := params.RetrieveDomain()
	if err != nil {
		assert.Fail(t, fmt.Sprintf("failed retrieve domain from %s", params.URL))
	}

	prov := CustomOauthServer{
		L:             logger.Std,
		Domain:        d,
		OauthServer:   srv,
		WithLoginPage: true,
		LoginPageHandler: func(w http.ResponseWriter, r *http.Request) {
			// // Simulate POST from login page
			u, err := url.Parse("http://127.0.0.1:9096/authorize?" + r.URL.RawQuery)
			if err != nil {
				assert.Fail(t, "failed to parse url")
			}

			jar, err := cookiejar.New(nil)
			if err != nil {
				assert.Fail(t, "failed initialize cookiesjar")
			}
			jar.SetCookies(u, r.Cookies())

			form := url.Values{}
			form.Add("username", "admin")
			form.Add("password", "pwd1234")

			req, err := http.NewRequest("POST", "", strings.NewReader(form.Encode()))
			req.URL = u
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			c := &http.Client{Jar: jar, Timeout: time.Second * 10}
			resp, err := c.Do(req)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			assert.Equal(t, 2, len(resp.Cookies()))
			assert.Equal(t, "JWT", resp.Cookies()[0].Name)
			assert.NotEqual(t, "", resp.Cookies()[0].Value, "token set")
			assert.Equal(t, 2678400, resp.Cookies()[0].MaxAge)
			assert.Equal(t, "XSRF-TOKEN", resp.Cookies()[1].Name)
			assert.NotEqual(t, "", resp.Cookies()[1].Value, "xsrf cookie set")

			claims, err := params.JwtService.Parse(resp.Cookies()[0].Value)
			assert.Nil(t, err)

			assert.Equal(t, token.User{Name: "admin", ID: "admin",
				Picture: "http://127.0.0.1:9096/avatar?user=admin", IP: ""}, *claims.User)

		},
	}

	router := http.NewServeMux()
	router.Handle("/auth/custom/", http.HandlerFunc(s.Handler))
	ts := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", 8080), Handler: router}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go prov.Run(ctx)
	go ts.ListenAndServe()

	defer func() {
		prov.Shutdown()
		_ = ts.Shutdown(context.TODO())
	}()

	time.Sleep(400 * time.Millisecond)

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	client := &http.Client{Jar: jar, Timeout: time.Second * 10}

	// check non-admin, permanent
	resp, err := client.Get("http://127.0.0.1:8080/auth/custom/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	t.Logf("resp %s", string(body))
	t.Logf("headers: %+v", resp.Header)

	// check avatar
	resp, err = client.Get("http://127.0.0.1:9096/avatar?user=dev_user")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, 960, len(body))
	t.Logf("headers: %+v", resp.Header)

	// check default login page
	prov.LoginPageHandler = nil
	resp, err = client.Get("http://127.0.0.1:8080/auth/custom/login?site=my-test-site")
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestCustProviderCancel(t *testing.T) {
	params := Params{Cid: "cid", Csecret: "csecret", URL: "http://127.0.0.1:8080", L: logger.Std,
		JwtService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func() (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
			DisableIAT:     true,
		}),
	}

	srv := initCustomProvider()
	d, _ := params.RetrieveDomain()

	prov := CustomOauthServer{
		L:             logger.Std,
		Domain:        d,
		OauthServer:   srv,
		WithLoginPage: false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() {
		prov.Run(ctx)
		done <- true
	}()
	cancel()

	select {
	case <-time.After(time.Second):
		t.Fail()
	case <-done:
	}
}

func initCustomProvider() *server.Server {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))

	// client memory store
	clientStore := store.NewClientStore()
	clientStore.Set("cid", &models.Client{
		ID:     "cid",
		Secret: "csecret",
		Domain: "http://127.0.0.1:8080",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		if r.ParseForm() != nil {
			return "", fmt.Errorf("no username and password in request")
		}
		if r.Form.Get("username") != "admin" || r.Form.Get("password") != "pwd1234" {
			return "", fmt.Errorf("wrong creds")
		}
		return "admin", nil
	})

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	return srv
}
