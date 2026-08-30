package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/v2/token"
)

func TestProviders_NewGoogle(t *testing.T) {
	r := NewGoogle(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "google", r.Name())

	t.Run("with all data", func(t *testing.T) {
		udata := UserData{"sub": "1234567890", "name": "test user", "picture": "http://demo.remark42.com/blah.png"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "test user", ID: "google_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("with no name", func(t *testing.T) {
		udata := UserData{"sub": "1234567890", "picture": "http://demo.remark42.com/blah.png"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "noname_1b30", ID: "google_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("with extra scopes", func(t *testing.T) {
		r := NewGoogle(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs",
			UserAttributes: map[string]string{"email": "email"}})
		assert.Equal(t, "google", r.Name())
		udata := UserData{"sub": "1234567890", "name": "test user", "picture": "http://demo.remark42.com/blah.png",
			"email": "test@email.com"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "test user", ID: "google_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
			Picture: "http://demo.remark42.com/blah.png", IP: "", Attributes: map[string]any{"email": "test@email.com"}}, user, "got %+v", user)
	})
}

func TestProviders_NewGithub(t *testing.T) {
	r := NewGithub(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "github", r.Name())

	t.Run("with all data", func(t *testing.T) {
		udata := UserData{"login": "lll", "name": "test user", "avatar_url": "http://demo.remark42.com/blah.png"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "test user", ID: "github_e80b2d2608711cbb3312db7c4727a46fbad9601a",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("with no name", func(t *testing.T) {
		// nil name in data (json response contains `"name": null`); using login, it's always required
		udata := UserData{"login": "lll", "name": nil, "avatar_url": "http://demo.remark42.com/blah.png"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "lll", ID: "github_e80b2d2608711cbb3312db7c4727a46fbad9601a",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("with extra scopes", func(t *testing.T) {
		withAttrs := NewGithub(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs",
			UserAttributes: map[string]string{"email": "email"}})
		assert.Equal(t, "github", withAttrs.Name())
		udata := UserData{"login": "lll", "name": "test user", "avatar_url": "http://demo.remark42.com/blah.png",
			"email": "test@email.com"}
		user := withAttrs.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "test user", ID: "github_e80b2d2608711cbb3312db7c4727a46fbad9601a",
			Picture: "http://demo.remark42.com/blah.png", IP: "", Attributes: map[string]any{"email": "test@email.com"}}, user, "got %+v", user)
	})

	t.Run("numeric id ignored by default", func(t *testing.T) {
		udata := UserData{"login": "lll", "name": "test user", "avatar_url": "http://demo.remark42.com/blah.png"}
		user := r.mapUser(udata, []byte(`{"id": 1345027, "login": "lll"}`))
		assert.Equal(t, "github_e80b2d2608711cbb3312db7c4727a46fbad9601a", user.ID, "login-based id kept")
	})
}

func TestProviders_NewGithubNumericID(t *testing.T) {
	r := NewGithub(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs", GithubNumericID: true})
	assert.Equal(t, "github", r.Name())

	t.Run("id from numeric account id", func(t *testing.T) {
		udata := UserData{"login": "lll", "name": "test user", "avatar_url": "http://demo.remark42.com/blah.png"}
		user := r.mapUser(udata, []byte(`{"id": 1345027, "login": "lll"}`))
		assert.Equal(t, token.User{Name: "test user", ID: "github_d4dc5da9a1e6bbd5d77920e4ea2ca91707e59083",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("recycled login maps to different users", func(t *testing.T) {
		udata := UserData{"login": "lll", "name": "test user"}
		victim := r.mapUser(udata, []byte(`{"id": 1345027, "login": "lll"}`))
		attacker := r.mapUser(udata, []byte(`{"id": 219851832, "login": "lll"}`))
		assert.Equal(t, "github_d4dc5da9a1e6bbd5d77920e4ea2ca91707e59083", victim.ID)
		assert.Equal(t, "github_d7f2f255cff0e923394424ee9038da06a4a12e89", attacker.ID)
		assert.NotEqual(t, victim.ID, attacker.ID, "same login with different accounts must not collide")
	})

	t.Run("renamed account keeps the same id", func(t *testing.T) {
		before := r.mapUser(UserData{"login": "lll"}, []byte(`{"id": 1345027, "login": "lll"}`))
		after := r.mapUser(UserData{"login": "renamed"}, []byte(`{"id": 1345027, "login": "renamed"}`))
		assert.Equal(t, before.ID, after.ID, "rename must not change the id")
	})

	t.Run("all-digit login does not collide with a numeric id", func(t *testing.T) {
		// github allows all-digit logins, so login "27385" and account id 27385 are different real users
		def := NewGithub(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
		byLogin := def.mapUser(UserData{"login": "27385"}, []byte(`{"id": 11210579, "login": "27385"}`))
		byNumeric := r.mapUser(UserData{"login": "1234"}, []byte(`{"id": 27385, "login": "1234"}`))
		assert.Equal(t, "github_f862a2565f61de2e7ebf5afed09fbe2e05bc9e8d", byLogin.ID)
		assert.Equal(t, "github_5b067825dfd5af0c41d1c1f6f16aad3ff3397473", byNumeric.ID)
		assert.NotEqual(t, byLogin.ID, byNumeric.ID, "login and numeric id spaces must not overlap")
	})

	t.Run("falls back to login without a usable numeric id", func(t *testing.T) {
		udata := UserData{"login": "lll", "name": "test user"}
		assert.Equal(t, "github_e80b2d2608711cbb3312db7c4727a46fbad9601a", r.mapUser(udata, nil).ID, "nil body")
		assert.Equal(t, "github_e80b2d2608711cbb3312db7c4727a46fbad9601a", r.mapUser(udata, []byte(`{"login": "lll"}`)).ID, "no id field")
		assert.Equal(t, "github_e80b2d2608711cbb3312db7c4727a46fbad9601a", r.mapUser(udata, []byte(`{"id": 0}`)).ID, "zero id")
	})
}

func TestProviders_NewGithubEnterprise(t *testing.T) {
	base := Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"}

	t.Run("default is public github.com", func(t *testing.T) {
		r := NewGithub(base)
		assert.Equal(t, "github", r.Name())
		assert.Equal(t, "https://github.com/login/oauth/authorize", r.endpoint.AuthURL)
		assert.Equal(t, "https://api.github.com/user", r.infoURL)
	})

	t.Run("enterprise base url", func(t *testing.T) {
		r, err := NewGithubEnterprise(base, "https://github.example.com")
		require.NoError(t, err)
		assert.Equal(t, "github", r.Name())
		assert.Equal(t, "https://github.example.com/login/oauth/authorize", r.endpoint.AuthURL)
		assert.Equal(t, "https://github.example.com/login/oauth/access_token", r.endpoint.TokenURL)
		assert.Equal(t, "https://github.example.com/api/v3/user", r.infoURL)
	})

	t.Run("trailing slash trimmed", func(t *testing.T) {
		r, err := NewGithubEnterprise(base, "https://github.example.com/")
		require.NoError(t, err)
		assert.Equal(t, "https://github.example.com/api/v3/user", r.infoURL)
	})

	t.Run("scheme-less base url treated as https", func(t *testing.T) {
		r, err := NewGithubEnterprise(base, "github.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://github.example.com/login/oauth/authorize", r.endpoint.AuthURL)
		assert.Equal(t, "https://github.example.com/login/oauth/access_token", r.endpoint.TokenURL)
		assert.Equal(t, "https://github.example.com/api/v3/user", r.infoURL)
	})

	t.Run("custom port kept", func(t *testing.T) {
		r, err := NewGithubEnterprise(base, "https://github.example.com:8443")
		require.NoError(t, err)
		assert.Equal(t, "https://github.example.com:8443/login/oauth/authorize", r.endpoint.AuthURL)
		assert.Equal(t, "https://github.example.com:8443/api/v3/user", r.infoURL)
	})

	t.Run("enterprise ids are seeded by instance", func(t *testing.T) {
		r, err := NewGithubEnterprise(base, "https://github.example.com")
		require.NoError(t, err)
		udata := UserData{"login": "lll", "name": "test user", "avatar_url": "http://github.example.com/blah.png"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "test user", ID: "github_699f98cb49b4f83acafcaec466524efac3d8f6de",
			Picture: "http://github.example.com/blah.png"}, user, "got %+v", user)
		// same login on public github.com hashes to a different id, so repointing does not inherit records
		pub := NewGithub(base)
		assert.NotEqual(t, pub.mapUser(UserData{"login": "lll"}, nil).ID, user.ID)
	})

	t.Run("enterprise numeric id is seeded by instance", func(t *testing.T) {
		r, err := NewGithubEnterprise(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs",
			GithubNumericID: true}, "https://github.example.com")
		require.NoError(t, err)
		user := r.mapUser(UserData{"login": "lll"}, []byte(`{"id": 1345027, "login": "lll"}`))
		assert.Equal(t, "github_6178076b17e83d66fc463e3dd89c3bf81a26dd83", user.ID)
		// without a usable numeric id it keeps the enterprise-seeded login, not the public one
		fallback := r.mapUser(UserData{"login": "lll"}, nil)
		assert.Equal(t, "github_699f98cb49b4f83acafcaec466524efac3d8f6de", fallback.ID)
	})

	t.Run("http and https on one host share the realm", func(t *testing.T) {
		httpsProv, err := NewGithubEnterprise(base, "https://github.example.com")
		require.NoError(t, err)
		httpProv, err := NewGithubEnterprise(base, "http://github.example.com")
		require.NoError(t, err)
		assert.Equal(t, httpsProv.mapUser(UserData{"login": "lll"}, nil).ID,
			httpProv.mapUser(UserData{"login": "lll"}, nil).ID)
	})

	t.Run("invalid base url is a registration error", func(t *testing.T) {
		for _, bad := range []string{"not a url", "ftp://github.example.com", "/only/path",
			"https://github.example.com?x=1", "https://github.example.com#frag", "https://user:pw@github.example.com",
			"https://", "https://github.example.com/api/v3", "https://github.example.com?",
			"https://:8443", "https://:443"} {
			_, err := NewGithubEnterprise(base, bad)
			assert.Error(t, err, "base %q should fail registration", bad)
		}
	})
}

func TestProviders_NewFacebook(t *testing.T) {
	r := NewFacebook(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "facebook", r.Name())

	t.Run("with all data", func(t *testing.T) {
		udata := UserData{"id": "myid", "name": "test user"}
		user := r.mapUser(udata, []byte(`{"picture": {"data": {"url": "http://demo.remark42.com/blah.png"} }}`))
		assert.Equal(t, token.User{Name: "test user", ID: "facebook_6e34471f84557e1713012d64a7477c71bfdac631",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("with no name", func(t *testing.T) {
		udata := UserData{"id": "myid", "name": ""}
		user := r.mapUser(udata, []byte(`{"picture": {"data": {"url": "http://demo.remark42.com/blah.png"} }}`))
		assert.Equal(t, token.User{Name: "facebook_6e34471", ID: "facebook_6e34471f84557e1713012d64a7477c71bfdac631",
			Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
	})

	t.Run("with extra scopes", func(t *testing.T) {
		r := NewFacebook(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs",
			UserAttributes: map[string]string{"email": "email"}})
		assert.Equal(t, "facebook", r.Name())
		udata := UserData{"id": "myid", "name": "test user", "email": "test@email.com"}
		user := r.mapUser(udata, []byte(`{"picture": {"data": {"url": "http://demo.remark42.com/blah.png"} }}`))
		assert.Equal(t, token.User{Name: "test user", ID: "facebook_6e34471f84557e1713012d64a7477c71bfdac631",
			Picture: "http://demo.remark42.com/blah.png", IP: "", Attributes: map[string]any{"email": "test@email.com"}},
			user, "got %+v", user)

	})
}

func TestProviders_NewYandex(t *testing.T) {
	r := NewYandex(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "yandex", r.Name())

	udata := UserData{"id": "1234567890", "display_name": "Vasya P", "default_avatar_id": "131652443"}
	user := r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "Vasya P", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "https://avatars.yandex.net/get-yapic/131652443/islands-200", IP: ""}, user, "got %+v", user)

	// "display_name": null, "default_avatar_id": null
	udata = UserData{"id": "1234567890", "login": "vasya", "display_name": nil, "real_name": "Vasya Pupkin", "default_avatar_id": nil}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "Vasya Pupkin", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "", IP: ""}, user, "got %+v", user)

	// empty "display_name", empty "default_avatar_id", empty "real_name"
	udata = UserData{"id": "1234567890", "login": "vasya", "display_name": "", "real_name": "", "default_avatar_id": ""}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "vasya", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "", IP: ""}, user, "got %+v", user)

	// "real_name": null
	udata = UserData{"id": "1234567890", "login": "vasya", "real_name": nil, "default_avatar_id": ""}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "vasya", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "", IP: ""}, user, "got %+v", user)
}

func TestProviders_NewTwitter(t *testing.T) {
	r := NewTwitter(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "twitter", r.Name())

	cases := []struct {
		udata    UserData
		uopts    []byte
		expected token.User
	}{
		{udata: UserData{"id_str": "myid", "name": "test user", "profile_image_url_https": "https://demo.remark42.com/blah.png"},
			uopts: []byte(``),
			expected: token.User{Name: "test user", ID: "twitter_6e34471f84557e1713012d64a7477c71bfdac631",
				Picture: "https://demo.remark42.com/blah.png", IP: ""},
		},
		{udata: UserData{"id_str": "124381237", "screen_name": "Bob", "name": "Robert Downey Jr.", "profile_image_url_https": ""},
			uopts: []byte(``),
			expected: token.User{Name: "Bob", ID: "twitter_63a6b20b6e17fb5e17f6c58b6223e3b760ad510e",
				Picture: "", IP: ""},
		},
		{udata: UserData{"id_str": "124381237", "name": "Robert Downey Jr.", "profile_image_url_https": "https://demo.remark42.com/blah.png"},
			uopts: []byte(``),
			expected: token.User{Name: "Robert Downey Jr.", ID: "twitter_63a6b20b6e17fb5e17f6c58b6223e3b760ad510e",
				Picture: "https://demo.remark42.com/blah.png", IP: ""},
		},
	}

	for i := range cases {
		c := cases[i]
		got := r.mapUser(c.udata, c.uopts)
		assert.Equal(t, c.expected, got, "got %+v", got)
	}

}

func TestProviders_NewPatreon(t *testing.T) {
	r := NewPatreon(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "patreon", r.Name())

	udata := UserData{}
	user := r.mapUser(udata, []byte(`{
		  "data": {
			"attributes": {
			  "email": "corgi@example.com",
			  "full_name": "Corgi The Dev",
			  "image_url": "https://c8.patreon.com/2/400/0000000"
			},
			"id": "0000000"
		}}`))
	assert.Equal(t, token.User{Name: "Corgi The Dev", ID: "patreon_4e079d0555e5a2b460969c789d3ad968a795921f",
		Picture: "https://c8.patreon.com/2/400/0000000", IP: ""}, user, "got %+v", user)

	udata = UserData{}
	user = r.mapUser(udata, []byte(`{
		  "data": {
			"attributes": {
			  "email": "corgi@example.com",
			  "full_name": "Corgi The Dev",
			  "image_url": "https://c8.patreon.com/2/400/0000000"
			},
			"id": "0000000",
			"relationships": {
				"pledges": {
					"data": [
						{
							"id": "0000000",
							"type": "pledge"
						}
					]
				}
			}
		}}`))
	assert.Equal(
		t,
		token.User{Name: "Corgi The Dev", ID: "patreon_4e079d0555e5a2b460969c789d3ad968a795921f",
			Picture: "https://c8.patreon.com/2/400/0000000", IP: "", Attributes: map[string]any{"is_paid_sub": true}},
		user,
		"got %+v",
		user,
	)
}

// distinct Patreon accounts must produce distinct local user IDs.
// the previous implementation hashed the uninitialized userInfo.ID, so every
// Patreon user collapsed into the same identity.
func TestProviders_NewPatreon_DistinctIDs(t *testing.T) {
	r := NewPatreon(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})

	alice := r.mapUser(UserData{}, []byte(`{"data":{"attributes":{"full_name":"Alice"},"id":"1111111"}}`))
	bob := r.mapUser(UserData{}, []byte(`{"data":{"attributes":{"full_name":"Bob"},"id":"9999999"}}`))

	assert.NotEqual(t, alice.ID, bob.ID, "different Patreon ids must map to different local user IDs")
	assert.Equal(t, "patreon_2ea6201a068c5fa0eea5d81a3863321a87f8d533", alice.ID)
	assert.Equal(t, "patreon_22067cb54a7b24764186f1e48cb4586772733cd7", bob.ID)

	empty := r.mapUser(UserData{}, []byte(`{"data":{"attributes":{"full_name":"Nobody"},"id":""}}`))
	assert.NotEqual(t, alice.ID, empty.ID, "empty Patreon id must not collide with a real one")
}

func TestProviders_NewMicrosoft(t *testing.T) {
	t.Run("default tenant", func(t *testing.T) {
		r := NewMicrosoft(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
		assert.Equal(t, "microsoft", r.Name())
		assert.Contains(t, r.endpoint.AuthURL, "/common/")

		udata := UserData{"id": "myid", "displayName": "test user"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{
			Name:    "test user",
			ID:      "microsoft_6e34471f84557e1713012d64a7477c71bfdac631",
			Picture: "https://graph.microsoft.com/beta/me/photo/$value",
		}, user, "got %+v", user)
	})

	t.Run("custom tenant", func(t *testing.T) {
		r := NewMicrosoft(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs",
			MicrosoftTenant: "my-tenant-id"})
		assert.Equal(t, "microsoft", r.Name())
		assert.Contains(t, r.endpoint.AuthURL, "/my-tenant-id/")
		assert.Contains(t, r.endpoint.TokenURL, "/my-tenant-id/")
	})

	t.Run("invalid tenant falls back to common", func(t *testing.T) {
		for _, tenant := range []string{"ten/ant", "ten..ant", "ten?ant", "ten#ant", "ten ant"} {
			r := NewMicrosoft(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs",
				MicrosoftTenant: tenant})
			assert.Contains(t, r.endpoint.AuthURL, "/common/", "tenant %q should fall back to common", tenant)
		}
	})
}

func TestProviders_NewDiscord(t *testing.T) {
	r := NewDiscord(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "discord", r.Name())

	t.Run("With all data", func(t *testing.T) {
		udata := UserData{"id": "248533295981532", "username": "test_user", "avatar": "374384984773"}
		user := r.mapUser(udata, nil)
		assert.Equal(t, token.User{Name: "test_user", ID: "discord_9b472605c1318483fb4b88f9acf22cdd4219f9a0",
			Picture: "https://cdn.discordapp.com/avatars/248533295981532/374384984773.webp"}, user, "got %+v", user)
	})

}
