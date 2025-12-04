package provider

import "strings"

type AccessTokenResponse struct {
	AccessToken  string   `json:"access_token"`
	ExpiresIn    int      `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	RefreshToken string   `json:"refresh_token"`
	Scope        []string `json:"scope,omitempty"`
}

func makeRedirectURL(url, path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimRight(url, "/") + strings.TrimSuffix(newPath, "/") + urlCallbackSuffix
}
