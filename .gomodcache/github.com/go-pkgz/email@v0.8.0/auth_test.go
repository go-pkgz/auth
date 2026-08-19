package email

import (
	"bytes"
	"net/smtp"
	"testing"
)

func TestLoginAuth(t *testing.T) {
	user := "user"
	password := "password"
	server := "servername"
	auth := newLoginAuth(user, password, server)

	mech, resp, err := auth.Start(&smtp.ServerInfo{Name: server, TLS: true})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if mech != "LOGIN" {
		t.Fatalf("start: got auth mechanism %s, expected %s", mech, "LOGIN")
	}
	if !bytes.Equal(resp, []byte(user)) {
		t.Fatalf("start: got response to server %s, expected %s", resp, user)
	}

	resp, err = auth.Next([]byte("Password"), true)
	if err != nil {
		t.Fatalf("next more = true: %v", err)
	}
	if !bytes.Equal(resp, []byte(password)) {
		t.Fatalf("next: got response to server %s, expected %s",
			resp, password)
	}

	_, err = auth.Next(nil, false)
	if err != nil {
		t.Fatalf("next more = false: %v", err)
	}
}

func TestLoginAuth_Start(t *testing.T) {
	var testcases = []struct {
		authName string
		server   *smtp.ServerInfo
		err      string
	}{
		{
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "servername", TLS: true},
		},
		{
			// OK to use LoginAuth on localhost without TLS
			authName: "localhost",
			server:   &smtp.ServerInfo{Name: "localhost", TLS: false},
		},
		{
			// NOT OK to use LoginAuth on non-localhost without TLS
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "servername", TLS: false},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "hacker", TLS: true},
			err:      "wrong host name",
		},
	}

	for i, tc := range testcases {
		auth := newLoginAuth("foo", "bar", tc.authName)
		_, _, err := auth.Start(tc.server)
		got := ""
		if err != nil {
			got = err.Error()
		}

		if got != tc.err {
			t.Errorf("#%d. got error = %q, want %q", i, got, tc.err)
		}
	}
}
