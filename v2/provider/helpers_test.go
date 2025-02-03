package provider

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_makeRedirectURL(t *testing.T) {
	type args struct {
		url  string
		path string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "", args: args{url: "https://some-site.com", path: "/"}, want: "https://some-site.com/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, makeRedirectURL(tt.args.url, tt.args.path), "makeRedirectURL(%v, %v)", tt.args.url, tt.args.path)
		})
	}
}
