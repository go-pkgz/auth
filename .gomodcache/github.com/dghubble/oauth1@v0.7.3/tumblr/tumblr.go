// Package tumblr provides constants for using OAuth 1 to access Tumblr.
package tumblr

import (
	"github.com/dghubble/oauth1"
)

// Endpoint is Tumblr's OAuth 1a endpoint.
var Endpoint = oauth1.Endpoint{
	RequestTokenURL: "https://www.tumblr.com/oauth/request_token",
	AuthorizeURL:    "https://www.tumblr.com/oauth/authorize",
	AccessTokenURL:  "https://www.tumblr.com/oauth/access_token",
}
