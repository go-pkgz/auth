package provider

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/nullrocks/identicon"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/token"
)

const devAuthPort = 8084

// DevAuthServer is a fake oauth server for development
// it provides stand-alone server running on its own port and pretending to be the real oauth2. It also provides
// Dev Provider the same way as normal providers do, i.e. like github, google and others.
// can run in interactive and non-interactive mode. In interactive mode login attempts will show login form to select
// desired user name, this is the mode used for development. Non-interactive mode for tests only.
type DevAuthServer struct {
	Provider  Service
	Automatic bool

	username string // unsafe, but fine for dev

	iconGen    *identicon.Generator
	httpServer *http.Server
	lock       sync.Mutex
}

// Run oauth2 dev server on port devAuthPort
func (d *DevAuthServer) Run() {
	d.username = "dev_user"
	log.Printf("[INFO] run local oauth2 dev server on %d, redir url=%s", devAuthPort, d.Provider.RedirectURL)
	d.lock.Lock()
	var err error
	d.iconGen, err = identicon.New("github", 5, 3)
	if err != nil {
		log.Printf("[WARN] can't create identicon, %s", err)
	}

	userFormTmpl, err := template.New("page").Parse(devUserFormTmpl)
	if err != nil {
		log.Printf("[WARN] can't parse user form template, %s", err)
		return
	}

	d.httpServer = &http.Server{
		Addr: fmt.Sprintf(":%d", devAuthPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[DEBUG] dev oauth request %s %s %+v", r.Method, r.URL, r.Header)
			switch {

			case strings.HasPrefix(r.URL.Path, "/login/oauth/authorize"):

				// first time it will be called without username and will ask for one
				if !d.Automatic && (r.ParseForm() != nil || r.Form.Get("username") == "") {

					formData := struct{ Query string }{Query: r.URL.RawQuery}

					if err = userFormTmpl.Execute(w, formData); err != nil {
						log.Printf("[WARN] can't write, %s", err)
					}
					return
				}

				if !d.Automatic {
					d.username = r.Form.Get("username")
				}

				state := r.URL.Query().Get("state")
				callbackURL := fmt.Sprintf("%s?code=g0ZGZmNjVmOWI&state=%s", d.Provider.RedirectURL, state)
				log.Printf("[DEBUG] callback url=%s", callbackURL)
				w.Header().Add("Location", callbackURL)
				w.WriteHeader(http.StatusFound)

			case strings.HasPrefix(r.URL.Path, "/login/oauth/access_token"):
				res := `{
					"access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
					"token_type":"bearer",
					"expires_in":3600,
					"refresh_token":"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
					"scope":"create",
					"state":"12345678"
					}`
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if _, err = w.Write([]byte(res)); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

			case strings.HasPrefix(r.URL.Path, "/user"):
				ava := fmt.Sprintf("http://127.0.0.1:%d/avatar?user=%s", devAuthPort, d.username)
				res := fmt.Sprintf(`{
					"id": "%s",
					"name":"%s",
					"picture":"%s"
					}`, d.username, d.username, ava)

				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if _, err = w.Write([]byte(res)); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

			case strings.HasPrefix(r.URL.Path, "/avatar"):
				user := r.URL.Query().Get("user")
				b, e := d.genAvatar(user)
				if e != nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if _, err = w.Write(b); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		}),
	}
	d.lock.Unlock()

	err = d.httpServer.ListenAndServe()
	log.Printf("[WARN] dev oauth2 server terminated, %s", err)
}

// Shutdown oauth2 dev server
func (d *DevAuthServer) Shutdown() {
	log.Print("[WARN] shutdown oauth2 dev server")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d.lock.Lock()
	if d.httpServer != nil {
		if err := d.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[DEBUG] oauth2 dev shutdown error, %s", err)
		}
	}
	log.Print("[DEBUG] shutdown dev oauth2 server completed")
	d.lock.Unlock()
}

// NewDev makes dev oauth2 provider for admin user
func NewDev(p Params) Service {
	return initService(p, Service{
		Name: "dev",
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://127.0.0.1:%d/login/oauth/authorize", devAuthPort),
			TokenURL: fmt.Sprintf("http://127.0.0.1:%d/login/oauth/access_token", devAuthPort),
		},
		RedirectURL: p.URL + "/auth/dev/callback",
		Scopes:      []string{"user:email"},
		InfoURL:     fmt.Sprintf("http://127.0.0.1:%d/user", devAuthPort),
		MapUser: func(data userData, _ []byte) token.User {
			userInfo := token.User{
				ID:      data.value("id"),
				Name:    data.value("name"),
				Picture: data.value("picture"),
			}
			return userInfo
		},
	})
}

func (d *DevAuthServer) genAvatar(user string) ([]byte, error) {
	if d.iconGen == nil {
		return nil, errors.Errorf("no iconGen, skip avatar generation for %s", user)
	}

	ii, err := d.iconGen.Draw(user) // Generate an IdentIcon
	if err != nil {
		return nil, errors.Wrapf(err, "failed to draw avatar for %s", user)
	}

	buf := &bytes.Buffer{}
	err = ii.Png(300, buf)
	return buf.Bytes(), err
}

var devUserFormTmpl = `
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
		<form action="/login/oauth/authorize?{{.Query}}" method="post">
			<header class="form-header">
				<h1><a href="https://github.com/go-pkgz/auth">GO-PKGZ/AUTH</a></h1>
				<p>Dev Provider</p>
			</header>
			<label>
				<span class="username-label">Username</span>
				<input
					class="username-input"
					type="text"
					name="username"
					value="dev_user"
					autofocus
				/>
			</label>
			<input type="submit" class="form-submit" value="Authorize" />
			<p class="notice">Not for production use</p>
		</form>
	</body>
	<script>
		var input = document.querySelector(".username-input");
		input.focus();
		input.setSelectionRange(0, input.value.length)
	</script>
</html>
`
