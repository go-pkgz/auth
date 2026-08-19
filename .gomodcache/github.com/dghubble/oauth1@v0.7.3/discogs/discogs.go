// Package discogs provides constants for using OAuth1 to access Discogs.
package discogs

import (
	"github.com/dghubble/oauth1"
)

// Endpoint is Discogs's OAuth 1.0a endpoint.
var Endpoint = oauth1.Endpoint{
	RequestTokenURL: "https://api.discogs.com/oauth/request_token",
	AuthorizeURL:    "https://www.discogs.com/oauth/authorize",
	AccessTokenURL:  "https://api.discogs.com/oauth/access_token",
}
