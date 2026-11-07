// Package provider implements all oauth2, oauth1 as well as custom and direct providers
package provider

import (
	"crypto/sha1" //nolint
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/dghubble/oauth1"
	"github.com/dghubble/oauth1/twitter"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/yandex"
)

// UserAttributes is the type that will be used to map user data from provider to token.User
type UserAttributes map[string]string

// NewGoogle makes google oauth2 provider
func NewGoogle(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name:     "google",
		endpoint: google.Endpoint,
		scopes:   []string{"https://www.googleapis.com/auth/userinfo.profile"},
		infoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				// encode email with provider name to avoid collision if same id returned by other provider
				ID:      "google_" + token.HashID(sha1.New(), data.Value("sub")),
				Name:    data.Value("name"),
				Picture: data.Value("picture"),
			}
			if userInfo.Name == "" {
				userInfo.Name = "noname_" + userInfo.ID[8:12]
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// githubEnterpriseURLs derives the OAuth and user-info URLs plus the id-namespace realm for a
// GitHub Enterprise Server instance from its base URL, e.g. "https://github.example.com". It
// returns the oauth2 endpoint, the user-info URL, the realm, and false when base is not a usable
// instance root, i.e. an absolute http(s) URL with a host and no userinfo, query, fragment, or path
// beyond "/". A host-less authority such as "https://:8443" (Host is ":8443" but Hostname is empty)
// is rejected too, so an empty host can never end up in the derived URLs.
func githubEnterpriseURLs(base string) (endpoint oauth2.Endpoint, infoURL, realm string, ok bool) {
	base = strings.TrimSpace(base)
	if base != "" && !strings.Contains(base, "://") && !strings.HasPrefix(base, "/") {
		base = "https://" + base // scheme-less value like "github.example.com" is the likeliest typo, treat as https
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return oauth2.Endpoint{}, "", "", false
	}
	// build the root from scheme and host only, never u.String(), so nothing from the raw input
	// (a trailing "/", a stray "?", an empty host) can be concatenated onto the derived paths
	root := u.Scheme + "://" + u.Host
	return oauth2.Endpoint{
		AuthURL:  root + "/login/oauth/authorize",
		TokenURL: root + "/login/oauth/access_token",
	}, root + "/api/v3/user", githubEnterpriseRealm(u), true
}

// githubEnterpriseRealm is the id namespace for an enterprise instance: the lowercase host with a
// single trailing DNS dot stripped, plus the port only when it is not the scheme default. Scheme
// and path are excluded so http and https on the same authority resolve to the same realm. The
// port is normalized through strconv.Atoi so ":0443" and ":443" do not read as different realms.
func githubEnterpriseRealm(u *url.URL) string {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port == "" {
		return host
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return net.JoinHostPort(host, port)
	}
	def := 443
	if u.Scheme == "http" {
		def = 80
	}
	if n == def {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(n))
}

// errInvalidGithubEnterpriseURL is returned by NewGithubEnterprise when the base URL is not a
// usable instance root. It carries none of the input, so a mistyped URL cannot leak through it.
var errInvalidGithubEnterpriseURL = errors.New("invalid github enterprise base url")

// NewGithub makes github oauth2 provider for public github.com.
func NewGithub(p Params) Oauth2Handler {
	return newGithubHandler(p, github.Endpoint, "https://api.github.com/user", "")
}

// NewGithubEnterprise makes a github oauth2 provider backed by a self-hosted GitHub Enterprise
// Server instance. baseURL is the instance root, e.g. "https://github.example.com"; the OAuth
// authorize/token and /api/v3 user-info URLs are derived from it. It returns an error when baseURL
// is not a usable http(s) instance root, so a mistyped URL fails registration instead of silently
// authenticating against public github.com. The instance authority seeds the user id namespace, so
// enterprise logins never collide with their public github.com namesakes. UserAttributes and
// GithubNumericID on p are honored, so the combination needs no hand-built Params.
func NewGithubEnterprise(p Params, baseURL string) (Oauth2Handler, error) {
	if p.L == nil {
		p.L = logger.NoOp
	}
	endpoint, infoURL, realm, ok := githubEnterpriseURLs(baseURL)
	if !ok {
		p.Logf("[WARN] invalid github enterprise url %s", redirectHostForLog(baseURL))
		return Oauth2Handler{}, errInvalidGithubEnterpriseURL
	}
	return newGithubHandler(p, endpoint, infoURL, realm), nil
}

// newGithubHandler builds the github oauth2 handler shared by public github.com and enterprise.
// realm is empty for public github.com, which keeps those ids byte-for-byte; a non-empty realm
// seeds both the login and the numeric id hashes so enterprise ids stay isolated from github.com.
func newGithubHandler(p Params, endpoint oauth2.Endpoint, infoURL, realm string) Oauth2Handler {
	if p.L == nil {
		p.L = logger.NoOp // mapUser below captures p, initOauth2Handler defaults its own copy only
	}
	return initOauth2Handler(p, Oauth2Handler{
		name:     "github",
		endpoint: endpoint,
		scopes:   []string{},
		infoURL:  infoURL,
		mapUser: func(data UserData, bdata []byte) token.User {
			userInfo := token.User{
				ID:      "github_" + token.HashID(sha1.New(), githubLoginSeed(realm, data.Value("login"))),
				Name:    data.Value("name"),
				Picture: data.Value("avatar_url"),
			}
			if p.GithubNumericID {
				// data.Value is not usable here, json numbers decode to float64 and format as "1.345027e+06".
				// the "gid:" prefix keeps numeric ids out of the login hash space, logins may be all-digit
				var uinfoJSON struct {
					ID int64 `json:"id"`
				}
				if err := json.Unmarshal(bdata, &uinfoJSON); err == nil && uinfoJSON.ID != 0 {
					userInfo.ID = "github_" + token.HashID(sha1.New(), githubNumericSeed(realm, uinfoJSON.ID))
				} else {
					// keep the login-based value, matching the default derivation and its recycling caveat.
					// with a realm this is the enterprise-seeded login, not the public github.com one
					p.Logf("[WARN] github numeric id not available, keeping login-based id")
				}
			}
			// github may have no user name, use login in this case
			if userInfo.Name == "" {
				userInfo.Name = data.Value("login")
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// githubLoginSeed returns the hash input for a login. Public github.com (empty realm) hashes the
// bare login, unchanged; an enterprise realm namespaces it as "ghes:<realm>:login:<login>".
func githubLoginSeed(realm, login string) string {
	if realm == "" {
		return login
	}
	return "ghes:" + realm + ":login:" + login
}

// githubNumericSeed returns the hash input for a numeric account id. Public github.com (empty
// realm) keeps the "gid:<id>" form, unchanged; an enterprise realm namespaces it as
// "ghes:<realm>:gid:<id>".
func githubNumericSeed(realm string, id int64) string {
	if realm == "" {
		return "gid:" + strconv.FormatInt(id, 10)
	}
	return "ghes:" + realm + ":gid:" + strconv.FormatInt(id, 10)
}

// NewFacebook makes facebook oauth2 provider
func NewFacebook(p Params) Oauth2Handler {

	// response format for fb /me call
	type uinfo struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}

	return initOauth2Handler(p, Oauth2Handler{
		name:     "facebook",
		endpoint: facebook.Endpoint,
		scopes:   []string{"public_profile"},
		infoURL:  "https://graph.facebook.com/me?fields=id,name,picture",
		mapUser: func(data UserData, bdata []byte) token.User {
			userInfo := token.User{
				ID:   "facebook_" + token.HashID(sha1.New(), data.Value("id")),
				Name: data.Value("name"),
			}
			if userInfo.Name == "" {
				userInfo.Name = userInfo.ID[0:16]
			}

			uinfoJSON := uinfo{}
			if err := json.Unmarshal(bdata, &uinfoJSON); err == nil {
				userInfo.Picture = uinfoJSON.Picture.Data.URL
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// NewYandex makes yandex oauth2 provider
func NewYandex(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name:     "yandex",
		endpoint: yandex.Endpoint,
		scopes:   []string{},
		// See https://tech.yandex.com/passport/doc/dg/reference/response-docpage/
		infoURL: "https://login.yandex.ru/info?format=json",
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:   "yandex_" + token.HashID(sha1.New(), data.Value("id")),
				Name: data.Value("display_name"), // using Display Name by default
			}
			if userInfo.Name == "" {
				userInfo.Name = data.Value("real_name") // using Real Name (== full name) if Display Name is empty
			}
			if userInfo.Name == "" {
				userInfo.Name = data.Value("login") // otherwise using login
			}

			if data.Value("default_avatar_id") != "" {
				userInfo.Picture = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", data.Value("default_avatar_id"))
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// NewTwitter makes twitter oauth2 provider
func NewTwitter(p Params) Oauth1Handler {
	return initOauth1Handler(p, Oauth1Handler{
		name: "twitter",
		conf: oauth1.Config{
			Endpoint: twitter.AuthorizeEndpoint,
		},
		infoURL: "https://api.twitter.com/1.1/account/verify_credentials.json",
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "twitter_" + token.HashID(sha1.New(), data.Value("id_str")),
				Name:    data.Value("screen_name"),
				Picture: data.Value("profile_image_url_https"),
			}
			if userInfo.Name == "" {
				userInfo.Name = data.Value("name")
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// NewBattlenet makes Battle.net oauth2 provider
func NewBattlenet(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name: "battlenet",
		endpoint: oauth2.Endpoint{ //nolint:gosec // G101 false positive, oauth endpoint urls are not credentials
			AuthURL:   "https://eu.battle.net/oauth/authorize",
			TokenURL:  "https://eu.battle.net/oauth/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		scopes:  []string{},
		infoURL: "https://eu.battle.net/oauth/userinfo",
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:   "battlenet_" + token.HashID(sha1.New(), data.Value("id")),
				Name: data.Value("battletag"),
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// NewMicrosoft makes microsoft azure oauth2 provider
func NewMicrosoft(p Params) Oauth2Handler {
	tenant := p.MicrosoftTenant
	if tenant == "" || strings.ContainsAny(tenant, "/?# \t\n\r") || strings.Contains(tenant, "..") {
		tenant = "common"
	}
	return initOauth2Handler(p, Oauth2Handler{
		name:     "microsoft",
		endpoint: microsoft.AzureADEndpoint(tenant),
		scopes:   []string{"User.Read"},
		infoURL:  "https://graph.microsoft.com/v1.0/me",
		// non-beta doesn't provide photo for consumers yet
		// see https://github.com/microsoftgraph/microsoft-graph-docs/issues/3990
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "microsoft_" + token.HashID(sha1.New(), data.Value("id")),
				Name:    data.Value("displayName"),
				Picture: "https://graph.microsoft.com/beta/me/photo/$value",
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// NewPatreon makes patreon oauth2 provider
func NewPatreon(p Params) Oauth2Handler {
	type uinfo struct {
		Data struct {
			Attributes struct {
				FullName string `json:"full_name"`
				ImageURL string `json:"image_url"`
			} `json:"attributes"`
			ID            string `json:"id"`
			Relationships struct {
				Pledges struct {
					Data []struct {
						ID   string `json:"id"`
						Type string `json:"type"`
					} `json:"data"`
				} `json:"pledges"`
			} `json:"relationships"`
		} `json:"data"`
	}

	return initOauth2Handler(p, Oauth2Handler{
		name: "patreon",
		// see https://docs.patreon.com/?shell#oauth
		endpoint: oauth2.Endpoint{ //nolint:gosec // G101 false positive, oauth endpoint urls are not credentials
			AuthURL:   "https://www.patreon.com/oauth2/authorize",
			TokenURL:  "https://api.patreon.com/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		scopes:  []string{},
		infoURL: "https://www.patreon.com/api/oauth2/api/current_user",

		mapUser: func(data UserData, bdata []byte) token.User {
			userInfo := token.User{}

			uinfoJSON := uinfo{}
			if err := json.Unmarshal(bdata, &uinfoJSON); err == nil {
				userInfo.ID = "patreon_" + token.HashID(sha1.New(), uinfoJSON.Data.ID)
				userInfo.Name = uinfoJSON.Data.Attributes.FullName
				userInfo.Picture = uinfoJSON.Data.Attributes.ImageURL

				// check if the user is your subscriber
				if len(uinfoJSON.Data.Relationships.Pledges.Data) > 0 {
					userInfo.SetPaidSub(true)
				}
			}
			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}

// NewDiscord makes discord oauth2 provider
func NewDiscord(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name: "discord",
		// see https://discord.com/developers/docs/topics/oauth2
		endpoint: oauth2.Endpoint{ //nolint:gosec // G101 false positive, oauth endpoint urls are not credentials
			AuthURL:  "https://discord.com/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
		infoURL: "https://discord.com/api/v10/users/@me",
		scopes:  []string{"identify"},
		mapUser: func(data UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "discord_" + token.HashID(sha1.New(), data.Value("id")),
				Name:    data.Value("username"),
				Picture: fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.webp", data.Value("id"), data.Value("avatar")),
			}

			for k, v := range p.UserAttributes {
				userInfo.SetStrAttr(v, data.Value(k))
			}
			return userInfo
		},
	})
}
