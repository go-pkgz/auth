package provider

import (
	"github.com/go-pkgz/auth/v2/token"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_NewTwitch(t *testing.T) {
	r := NewTwitch(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "twitch", r.Name())

	user := r.mapUser([]byte(`{
	  "data": [
		{
		  "id": "141981764",
		  "login": "twitchdev",
		  "display_name": "TwitchDev",
		  "type": "",
		  "broadcaster_type": "partner",
		  "description": "Supporting third-party developers building Twitch integrations from chatbots to game integrations.",
		  "profile_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
		  "offline_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/3f13ab61-ec78-4fe6-8481-8682cb3b0ac2-channel_offline_image-1920x1080.png",
		  "view_count": 5980557,
		  "email": "not-real@email.com",
		  "created_at": "2016-12-14T20:32:28Z"
		}
	  ]
	}`))
	assert.Equal(t, token.User{
		Name:    "TwitchDev",
		ID:      "twitch_f35163dedfaa9e88c74a285225c5a120bb7fe07e",
		Picture: "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
	}, user, "got %+v", user)

	user = r.mapUser([]byte(`{
	  "data": [
		{
		  "id": "141981764",
		  "login": "twitchdev",
		  "display_name": "",
		  "type": "",
		  "broadcaster_type": "partner",
		  "description": "Supporting third-party developers building Twitch integrations from chatbots to game integrations.",
		  "profile_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
		  "offline_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/3f13ab61-ec78-4fe6-8481-8682cb3b0ac2-channel_offline_image-1920x1080.png",
		  "view_count": 5980557,
		  "email": "not-real@email.com",
		  "created_at": "2016-12-14T20:32:28Z"
		}
	  ]
	}`))
	assert.Equal(t, token.User{
		Name:    "twitchdev",
		ID:      "twitch_f35163dedfaa9e88c74a285225c5a120bb7fe07e",
		Picture: "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
	}, user, "got %+v", user)

	user = r.mapUser([]byte(`{
	  "data": [
		{
		  "id": "141981764",
		  "login": "",
		  "display_name": "",
		  "type": "",
		  "broadcaster_type": "partner",
		  "description": "Supporting third-party developers building Twitch integrations from chatbots to game integrations.",
		  "profile_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
		  "offline_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/3f13ab61-ec78-4fe6-8481-8682cb3b0ac2-channel_offline_image-1920x1080.png",
		  "view_count": 5980557,
		  "email": "not-real@email.com",
		  "created_at": "2016-12-14T20:32:28Z"
		}
	  ]
	}`))
	assert.Equal(t, token.User{
		Name:    "not-real@email.com",
		ID:      "twitch_f35163dedfaa9e88c74a285225c5a120bb7fe07e",
		Picture: "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
	}, user, "got %+v", user)

	user = r.mapUser([]byte(`{
	  "data": [
		{
		  "id": "141981764",
		  "login": "",
		  "display_name": "",
		  "type": "",
		  "broadcaster_type": "partner",
		  "description": "Supporting third-party developers building Twitch integrations from chatbots to game integrations.",
		  "profile_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
		  "offline_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/3f13ab61-ec78-4fe6-8481-8682cb3b0ac2-channel_offline_image-1920x1080.png",
		  "view_count": 5980557,
		  "email": "",
		  "created_at": "2016-12-14T20:32:28Z"
		}
	  ]
	}`))
	assert.Equal(t, token.User{
		Name:    "twitch_141981764",
		ID:      "twitch_f35163dedfaa9e88c74a285225c5a120bb7fe07e",
		Picture: "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
	}, user, "got %+v", user)
}
