package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"golang.org/x/oauth2"
	"gopkg.in/oauth2.v3/server"
)

const custOAuthPort = 9096

// CustomProviderOpt are options to start go-oauth2/oauth2 server
type CustomProviderOpt struct {
	WithLoginPage    bool
	LoginPageHandler func(w http.ResponseWriter, r *http.Request)
	Cid              string
}

// CustomOauthServer is a go-oauth2/oauth2 server running on its own port
type CustomOauthServer struct {
	logger.L
	// Domain corresponds to the root host specified without port
	Domain string
	// WithLoginPage: redirect to login html page if true
	WithLoginPage bool
	// LoginPageHandler is handler for user-defined login page
	LoginPageHandler func(w http.ResponseWriter, r *http.Request)
	httpServer       *http.Server
	// OauthServer is instance of go-oauth2/oauth2 server
	OauthServer *server.Server
	lock        sync.Mutex
}

// Run starts serving on custOauthPort
func (c *CustomOauthServer) Run(ctx context.Context) {
	c.Logf("[INFO] run local go-oauth2/oauth2 server on %s:%d", c.Domain, custOAuthPort)
	c.lock.Lock()

	c.httpServer = &http.Server{
		Addr: fmt.Sprintf(":%d", custOAuthPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/authorize"):
				c.handleAuthorize(w, r)
			case strings.HasSuffix(r.URL.Path, "/access_token"):
				if err := c.OauthServer.HandleTokenRequest(w, r); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			case strings.HasPrefix(r.URL.Path, "/user"):
				c.handleUserInfo(w, r)
			case strings.HasPrefix(r.URL.Path, "/avatar"):
				c.handleAvatar(w, r)
			default:
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}),
	}
	c.lock.Unlock()

	go func() {
		<-ctx.Done()
		c.Logf("[DEBUG] cancellation via context, %v", ctx.Err())
		c.Shutdown()
	}()

	err := c.httpServer.ListenAndServe()
	c.Logf("[WARN] go-oauth2/oauth2 server terminated, %s", err)
}

func (c *CustomOauthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// called for first time, ask for username
	if c.WithLoginPage || c.LoginPageHandler != nil {
		if r.ParseForm() != nil || r.Form.Get("username") == "" {
			// show default template if user-defined function not specified
			if c.LoginPageHandler != nil {
				c.LoginPageHandler(w, r)
				return
			}
			userLoginTmpl, err := template.New("page").Parse(defaultLoginTmpl)
			if err != nil {
				c.Logf("[ERROR] can't parse user login template, %s", err)
				return
			}

			formData := struct{ Query string }{Query: r.URL.RawQuery}

			if err := userLoginTmpl.Execute(w, formData); err != nil {
				c.Logf("[WARN] can't write, %s", err)
			}
			return
		}
	}

	err := c.OauthServer.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (c *CustomOauthServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	ti, err := c.OauthServer.ValidationBearerToken(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	userID := ti.GetUserID()

	ava := fmt.Sprintf(c.Domain+":%d/avatar?user=%s", custOAuthPort, userID)
	res := fmt.Sprintf(`{
					"id": "%s",
					"name":"%s",
					"picture":"%s"
					}`, userID, userID, ava)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if _, err := w.Write([]byte(res)); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (c *CustomOauthServer) handleAvatar(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	b, err := avatar.GenerateAvatar(user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err = w.Write(b); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Shutdown go-oauth2/oauth2 server
func (c *CustomOauthServer) Shutdown() {
	c.Logf("[WARN] shutdown go-oauth2/oauth2 server")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.lock.Lock()
	if c.httpServer != nil {
		if err := c.httpServer.Shutdown(ctx); err != nil {
			c.Logf("[DEBUG] go-oauth2/oauth2 shutdown error, %s", err)
		}
	}
	c.Logf("[DEBUG] shutdown go-oauth2/oauth2 server completed")
	c.lock.Unlock()
}

// NewCustHandler creates a handler for go-oauth2/oauth2 server
func NewCustHandler(p Params) Oauth2Handler {
	d, err := p.RetrieveDomain()
	if err != nil {
		p.Logf("[ERROR] can't retrieve domain from service URL %s", p.URL)
	}

	return initOauth2Handler(p, Oauth2Handler{
		name: "custom",
		endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf(d+":%d/authorize", custOAuthPort),
			TokenURL: fmt.Sprintf(d+":%d/access_token", custOAuthPort),
		},
		scopes:  []string{"user:email"},
		infoURL: fmt.Sprintf(d+":%d/user", custOAuthPort),
		mapUser: func(data userData, _ []byte) token.User {
			userInfo := token.User{
				ID:      data.value("id"),
				Name:    data.value("name"),
				Picture: data.value("picture"),
			}
			return userInfo
		},
	})
}

var defaultLoginTmpl = `
<html>
	<head>
		<title>Dev OAuth</title>
		<style>
			body {
				text-align: center;
			}

			a {
				color: hsl(200, 50%, 50%);
				text-decoration-color: hsla(200, 50%, 50%, 0.5);
			}

			a:hover {
				color: hsl(200, 50%, 70%);
				text-decoration-color: hsla(200, 50%, 70%, 0.5);
			}
			
			form {
				font-family: Helvetica, Arial, sans-serif;
				margin: 100px auto;
				display: inline-block;
				padding: 1em;
				box-shadow: 0 0 0.1rem rgba(0, 0, 0, 0.2), 0 0 0.4rem rgba(0, 0, 0, 0.1);
			}

			.form-header {
				text-align: center;
			}

			.form-header h1 {
				margin: 0;
			}

			.form-header h1 a:not(:hover) {
				text-decoration: none;
			}

			.form-header p {
				opacity: 0.6;
				margin-top: 0;
				margin-bottom: 2rem;
			}

			.username-label {
				opacity: 0.6;
				font-size: 0.8em;
			}

			.username-input {
				font-size: inherit;
				margin: 0;
				width: 100%;
				text-align: inherit;
			}

			.form-submit {
				border: none;
				background: hsl(200, 50%, 50%);
				color: white;
				font: inherit;
				padding: 0.4em 0.8em 0.3em 0.8em;
				border-radius: 0.2em;
				width: 100%;
			}

			.form-submit:hover,
			.form-submit:focus {
				background-color: hsl(200, 50%, 70%);
			}

			.form-submit:active {
				background-color: hsl(200, 80%, 70%);
			}

			.username-label,
			.username-input,
			.form-submit {
				display: block;
				margin-bottom: 0.4rem;
			}

			.notice {
				margin: 0;
				margin-top: 2rem;
				font-size: 0.8em;
				opacity: 0.6;
			}
		</style>
	</head>
	<body>
		<form action="/login/oauth/authorize?{{.Query}}" method="POST">
			<header class="form-header">
				<h1><a href="https://github.com/go-oauth2/oauth2">go-oauth2/oauth2</a></h1>
				<p>Golang OAuth 2.0 Server</p>
			</header>
			<label>
				<span class="username-label">Username</span>
				<input
					class="username-input"
					type="text"
					name="username"
					value=""
					autofocus
				/>
			</label>

			<label>
			<span class="username-label">Password</span>
			<input
				class="username-input"
				type="password"
				name="password"
				value=""
				autofocus
			/>
			</label>

			<input type="submit" class="form-submit" value="Authorize" />
			<p class="notice"></p>
		</form>
	</body>
	<script>
		var input = document.querySelector(".username-input");
		input.focus();
		input.setSelectionRange(0, input.value.length)
	</script>
</html>
`
