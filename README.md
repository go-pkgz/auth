# auth - authentication via oauth2 [![Build Status](https://travis-ci.org/go-pkgz/auth.svg?branch=master)](https://travis-ci.org/go-pkgz/auth) [![Coverage Status](https://coveralls.io/repos/github/go-pkgz/auth/badge.svg?branch=master)](https://coveralls.io/github/go-pkgz/auth?branch=master) [![godoc](https://godoc.org/github.com/go-pkgz/auth?status.svg)](https://godoc.org/github.com/go-pkgz/auth)



This library provides "social login" with Github, Google, Facebook and Yandex.  

- Multiple oauth2 providers can be used at the same time
- Special `dev` provider allows local testing and development
- JWT stored in a secure cookie with XSRF protection. Cookies can be session-only
- Minimal scopes with user name, id and picture (avatar) only
- Integrated avatar proxy with FS, boltdb and gridfs storages
- Support of user-defined storages for avatars
- Black list with user-defined validator
- Multiple aud (audience) supported
- Secure key with customizable `SecretReader`
- Ability to store extra information to token and retrieve on login
- Pre-auth and post-auth hooks to handle custom use cases. 
- Middleware for easy integration into http routers

## Install

`go install github.com/go-pkgz/auth`

## Usage

Example with chi router:

```go

func main() {
	/// define options
	options := auth.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { // secret key for JWT
			return "secret", nil
		}),
		TokenDuration:  time.Hour,
		CookieDuration: time.Hour * 24,
		Issuer:         "my-test-app",
		URL:            "http://127.0.0.1:8080",
		AvatarStore:    avatar.NewLocalFS("/tmp"),
		Validator: token.ValidatorFunc(func(_ string, claims token.Claims) bool {
			// allow only dev_* names
			return claims.User != nil && strings.HasPrefix(claims.User.Name, "dev_")
		}),
	}

	// create auth service with providers
	service := auth.NewService(options)
	service.AddProvider("github", "<Client ID>", "<Client Secret>")   // add github provider
	service.AddProvider("facebook", "<Client ID>", "<Client Secret>") // add facebook provider

	// retrieve auth middleware
	m := service.Middleware()

	// setup http server
	router := chi.NewRouter()
	router.Get("/open", openRouteHandler)                      // open api
	router.With(m.Auth).Get("/private", protectedRouteHandler) // protected api

	// setup auth routes
	authRoutes, avaRoutes := service.Handlers()
	router.Mount("/auth", authRoutes)  // add auth handlers
	router.Mount("/avatar", avaRoutes) // add avatar handler

	log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Middleware

`github.com/go-pkgz/auth/middleware` provides ready-to-use middleware.

- `middleware.Auth` - requires authenticated user
- `middleware.Admin` - requires authenticated and admin user
- `middleware.Trace` - doesn't require authenticated user, but adds user info to request

## Details

Generally, adding support of `auth` includes a few relatively simple steps:

1. Setup `auth.Opts` structure with all parameters. Each of them [documented](https://github.com/go-pkgz/auth/blob/master/auth.go#L29) and most of parameters are optional and have sane defaults.
2. [Create](https://github.com/go-pkgz/auth/blob/master/auth.go#L56) the new `auth.Service` with provided options.
3. [Add all](https://github.com/go-pkgz/auth/blob/master/auth.go#L149) desirable authentication providers. Currently supported Github, Google, Facebook and Yandex 
4. Retrieve [middleware](https://github.com/go-pkgz/auth/blob/master/auth.go#L144) and [http handlers](https://github.com/go-pkgz/auth/blob/master/auth.go#L105) from `auth.Service`
5. Wire auth and avatar handlers into http router as sub–routes.

### API

For the example above authentication handlers wired as `/auth` and provides:

- `/auth/<provider>/login?id=<site_id>&from=<redirect_url>` - site_id used as `aud` claim for the token and can be processed by `SecretReader` to load/retrieve/define different secrets. redirect_url is the url to redirect after successful login.
- `/avatar/<avatar_id>` - returns the avatar (image). Links to those pictures added into user info automatically, for details see "Avatar proxy"
- `/auth/<provider>/logout` and `/auth/logout` - invalidate "session" by removing JWT cookie
- `/auth/list` - gives a json list of active providers 
- `/auth/user` - returns `token.User` (json)

### User info

Middleware populates `token.User` to request's context. It can be loaded with `token.GetUserInfo(r *http.Request) (user User, err error)` or `token.MustGetUserInfo(r *http.Request) User` functions.

`token.User` object includes all fields retrieved from oauth2 provider:
- `Name` - user name
- `ID` - hash of user id
- `Picture` - full link to proxied avatar (see "Avatar proxy")

It also has placeholders for fields application can populate with custom `token.ClaimsUpdater` (see "Customization")

- `IP`  - hash of user's IP address
- `Email` - user's email
- `Attributes` - map of string:any-value. To simplify management of this map some setters and getters provides, for example `users.StrAttr`, `user.SetBoolAttr` and so on. See [user.go](https://github.com/go-pkgz/auth/blob/master/token/user.go) for more details.
 
   
### Avatar proxy

Direct links to avatars won't survive any real-life usage if they linked from a public page. For example, page [like this](https://remark42.com/demo/) may have hundreds of avatars and, most likely, will trigger throttling on provider's side. To eliminate such restriction `auth` library provides and automatic proxy

- On each login the proxy will retrieve user's picture and save it to `AvatarStore`
- Local (proxied) link to avatar included in user's info (jwt token)
- API for avatar removal provided as a part of `AvatarStore`
- User can leverage one of provided stores:
    - `avatar.LocalFS` - file system, each avatar in a separate file
    - `avatar.BoltDB`  - a single [boltdb](https://github.com/coreos/bbolt) file (embedded KV store).
    - `avatar.GridFS` - external [GridFS](https://docs.mongodb.com/manual/core/gridfs/) (mongo db).
- In case of need a custom implementation of other stores can be passed in and used by `auth` library. Each store has to implement `avatar.Store` [interface](https://github.com/go-pkgz/auth/blob/master/avatar/store.go#L25).
- All avatar-related setup done as a part of `auth.Opts` and needs:
    - `AvatarStore` - avatar store to use, i.e. `avatar.NewLocalFS("/tmp/avatars")`
    - `AvatarRoutePath` - route prefix for direct links to proxied avatar. For example `/api/v1/avatars` will make full links links this - `http://example.com/api/v1/avatars/1234567890123.image`. The url will be stored in user's token and retrieved by middleware (see "User Info")
    - `AvatarResizeLimit` - size (in pixel) used to resize avatar. Pls note - resize happens once as a part of `Put` call, i.e. on login. 0 size (default) disables resizing.      

### Customization

There are several ways to adjust functionality of the library:

1. `SecretReader` - interface with a single method `Get(aud string) string` to return secret used to sign/verify JWT
1. `ClaimsUpdater` - interface with `Update(claims Claims) Claims` method. This is the primary way to alter the token at login time and add any attributes, set ip/email and so on.
2. `Validator` - interface with `Validate(token string, claims Claims) bool` method. This is post-token hook and will be called on each request wrapped with `Auth` middleware. This will be the place for some special logic to reject some token and/or users.

All of those interfaces have corresponding Func wrappers (adapters) - `SecretFunc`, `ClaimsUpdFunc` and `ValidatorFunc`.

### Implementing black list logic or some other filters

Restricting some users or some tokens is two step process:

- `ClaimsUpdater` sets some attributes, like `blocked` (or `allowed`)
- `Validator` checks those attributes and returns true/false 

_This technic used in the [example](https://github.com/go-pkgz/auth/blob/master/_example/backend/main.go#L27) code_

The process can be simplified by doing all checks directly in `Validator`, but depends on particular case such solution
can be too expensive because `Validator` runs on each request as a part of auth middleware. In contrast, `ClaimsUpdater` called on token creation/refresh only.


### Dev provider

Working with oauth2 providers can be a pain, especially during development phase. A special, development-only provider `dev` can make it less painful. This one can be registered directly, i.e. `service.AddProvider("dev", "", "")` and should be activated like this:

```go
	// runs dev oauth2 server on :8084
	go func() {
		p, err := service.Provider("dev")
		if err != nil {
			log.Fatal(err)
		}
		devAuthServer := provider.DevAuthServer{Provider: p}
		devAuthServer.Run()
	}()
```

It will run fake aouth2 "server" on port :8084 and user could login with any user name. See [example](https://github.com/go-pkgz/auth/blob/master/_example/backend/main.go) for more details. 

_Warning: this is not the real oauth2 server but just a small fake thing for development and testing only. Don't use `dev` provider with any production code._

    
## Register oauth2 providers

Authentication handled by external providers. You should setup oauth2 for all (or some) of them to allow users to authenticate. It is not mandatory to have all of them, but at least one should be correctly configured.

#### Google Auth Provider

1.  Create a new project: https://console.developers.google.com/project
2.  Choose the new project from the top right project dropdown (only if another project is selected)
3.  In the project Dashboard center pane, choose **"API Manager"**
4.  In the left Nav pane, choose **"Credentials"**
5.  In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
6.  In the center pane, choose **"Credentials"** tab.
    * Open the **"New credentials"** drop down
    * Choose **"OAuth client ID"**
    * Choose **"Web application"**
    * Application name is freeform, choose something appropriate
    * Authorized origins is your domain ex: `https://example.mysite.com`
    * Authorized redirect URIs is the location of oauth2/callback constructed as domain + `/auth/google/callback`, ex: `https://example.mysite.com/auth/google/callback`
    * Choose **"Create"**
7.  Take note of the **Client ID** and **Client Secret**

_instructions for google oauth2 setup borrowed from [oauth2_proxy](https://github.com/bitly/oauth2_proxy)_

#### GitHub Auth Provider

1.  Create a new **"OAuth App"**: https://github.com/settings/developers
1.  Fill **"Application Name"** and **"Homepage URL"** for your site
1.  Under **"Authorization callback URL"** enter the correct url constructed as domain + `/auth/github/callback`. ie `https://example.mysite.com/auth/github/callback`
1.  Take note of the **Client ID** and **Client Secret**

#### Facebook Auth Provider

1.  From https://developers.facebook.com select **"My Apps"** / **"Add a new App"**
1.  Set **"Display Name"** and **"Contact email"**
1.  Choose **"Facebook Login"** and then **"Web"**
1.  Set "Site URL" to your domain, ex: `https://example.mysite.com`
1.  Under **"Facebook login"** / **"Settings"** fill "Valid OAuth redirect URIs" with your callback url constructed as domain + `/auth/facebook/callback`
1.  Select **"App Review"** and turn public flag on. This step may ask you to provide a link to your privacy policy.

#### Yandex Auth Provider

1.  Create a new **"OAuth App"**: https://oauth.yandex.com/client/new
1.  Fill **"App name"** for your site
1.  Under **Platforms** select **"Web services"** and enter **"Callback URI #1"** constructed as domain + `/auth/yandex/callback`. ie `https://example.mysite.com/auth/yandex/callback`
1.  Select **Permissions**. You need following permissions only from the **"Yandex.Passport API"** section:
    * Access to user avatar
    * Access to username, first name and surname, gender
1.  Fill out the rest of fields if needed
1.  Take note of the **ID** and **Password**

For more details refer to [Yandex OAuth](https://tech.yandex.com/oauth/doc/dg/concepts/about-docpage/) and [Yandex.Passport](https://tech.yandex.com/passport/doc/dg/index-docpage/) API documentation.


## Status 

The library extracted from [remark42](https://github.com/umputun/remark) project. The original code in production use on multiple sites and seems to work fine. 

`go-pkgz/auth` library still in beta and until version 1 released some breaking changes still possible.