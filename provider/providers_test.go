package provider

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-pkgz/auth/token"
)

func TestProviders_NewGoogle(t *testing.T) {
	r := NewGoogle(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "google", r.Name())

	udata := userData{"sub": "1234567890", "name": "test user", "picture": "http://demo.remark42.com/blah.png"}
	user := r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "test user", ID: "google_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)

	// no name in data
	udata = userData{"sub": "1234567890", "picture": "http://demo.remark42.com/blah.png"}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "noname_1b30", ID: "google_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
}

func TestProviders_NewGithub(t *testing.T) {
	r := NewGithub(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "github", r.Name())

	udata := userData{"login": "lll", "name": "test user", "avatar_url": "http://demo.remark42.com/blah.png"}
	user := r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "test user", ID: "github_e80b2d2608711cbb3312db7c4727a46fbad9601a",
		Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)

	// nil name in data (json response contains `"name": null`); using login, it's always required
	udata = userData{"login": "lll", "name": nil, "avatar_url": "http://demo.remark42.com/blah.png"}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "lll", ID: "github_e80b2d2608711cbb3312db7c4727a46fbad9601a",
		Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
}

func TestProviders_NewFacebook(t *testing.T) {
	r := NewFacebook(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "facebook", r.Name())

	udata := userData{"id": "myid", "name": "test user"}
	user := r.mapUser(udata, []byte(`{"picture": {"data": {"url": "http://demo.remark42.com/blah.png"} }}`))
	assert.Equal(t, token.User{Name: "test user", ID: "facebook_6e34471f84557e1713012d64a7477c71bfdac631",
		Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)

	udata = userData{"id": "myid", "name": ""}
	user = r.mapUser(udata, []byte(`{"picture": {"data": {"url": "http://demo.remark42.com/blah.png"} }}`))
	assert.Equal(t, token.User{Name: "facebook_6e34471", ID: "facebook_6e34471f84557e1713012d64a7477c71bfdac631",
		Picture: "http://demo.remark42.com/blah.png", IP: ""}, user, "got %+v", user)
}

func TestProviders_NewYandex(t *testing.T) {
	r := NewYandex(Params{URL: "http://demo.remark42.com", Cid: "cid", Csecret: "cs"})
	assert.Equal(t, "yandex", r.Name())

	udata := userData{"id": "1234567890", "display_name": "Vasya P", "default_avatar_id": "131652443"}
	user := r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "Vasya P", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "https://avatars.yandex.net/get-yapic/131652443/islands-200", IP: ""}, user, "got %+v", user)

	// "display_name": null, "default_avatar_id": null
	udata = userData{"id": "1234567890", "login": "vasya", "display_name": nil, "real_name": "Vasya Pupkin", "default_avatar_id": nil}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "Vasya Pupkin", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "", IP: ""}, user, "got %+v", user)

	// empty "display_name", empty "default_avatar_id", empty "real_name"
	udata = userData{"id": "1234567890", "login": "vasya", "display_name": "", "real_name": "", "default_avatar_id": ""}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "vasya", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "", IP: ""}, user, "got %+v", user)

	// "real_name": null
	udata = userData{"id": "1234567890", "login": "vasya", "real_name": nil, "default_avatar_id": ""}
	user = r.mapUser(udata, nil)
	assert.Equal(t, token.User{Name: "vasya", ID: "yandex_01b307acba4f54f55aafc33bb06bbbf6ca803e9a",
		Picture: "", IP: ""}, user, "got %+v", user)
}

func TestRetrieveDomain(t *testing.T) {
	cases := []struct {
		name     string
		in       Params
		expected string
		willFail bool
	}{
		{"with scheme and port", Params{URL: "https://mydomain.com:8080"}, "https://mydomain.com", false},
		{"with scheme and w/o port", Params{URL: "https://mysite.com"}, "https://mysite.com", false},
		{"with scheme w/o port", Params{URL: "http://127.0.0.1"}, "http://127.0.0.1", false},
		{"with scheme w/o port", Params{URL: "https://mydomain.com:8080:39"}, "https://mydomain.com", true},
	}

	for i := range cases {
		c := cases[i]
		got, err := c.in.RetriveDomain()
		if err != nil {
			if !c.willFail {
				assert.Fail(t, fmt.Sprintf("case %s failed, not expected error occured. %s", c.name, err))
			}
			continue
		}

		assert.Equal(t, c.expected, got)
	}
}
