package sender

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-pkgz/auth/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailSendContextCanceled(t *testing.T) {
	// port 1 is not listening, a canceled context has to end the call before any connection attempt
	client := NewEmailClient(EmailParams{Host: "127.0.0.1", Port: 1, From: "test@example.com",
		Subject: "test email", TimeOut: time.Minute}, logger.Std)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	st := time.Now()
	err := client.SendContext(ctx, "to@example.com", "test body")
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(st), time.Second*5, "returned on the context instead of the connection timeout")
}

func TestEmailSend(t *testing.T) {
	if _, ok := os.LookupEnv("SEND_EMAIL_TEST"); !ok {
		t.Skip()
	}
	p := EmailParams{
		From:        "test@umputun.com",
		ContentType: "text/html",
		Host:        "192.168.1.24",
		Port:        25,
		Subject:     "test email",
	}
	client := NewEmailClient(p, logger.Std)

	msg := `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<body>
<h2>rest</h2>
<pre>xyz</pre>
</body>
</html>
`
	err := client.Send("sys@umputun.dev", msg)
	assert.NoError(t, err)
}

func TestEmail_New(t *testing.T) {
	p := EmailParams{
		Host:               "127.0.0.2",
		From:               "from@example.com",
		SMTPUserName:       "user",
		SMTPPassword:       "pass",
		Subject:            "subj",
		ContentType:        "text/html",
		Charset:            "UTF-8",
		LoginAuth:          true,
		StartTLS:           true,
		TLS:                true,
		InsecureSkipVerify: true,
	}
	e := NewEmailClient(p, logger.Std)
	assert.Equal(t, p, e.EmailParams)
}

func TestEmail_SendDoesNotLogBody(t *testing.T) {
	const secretBody = "Confirmation token: super-secret-magic-link-XYZ"
	var buf strings.Builder
	capturing := logger.Func(func(format string, args ...any) {
		fmt.Fprintf(&buf, format, args...)
	})
	p := EmailParams{Host: "127.0.0.2", Port: 25, From: "from@example.com",
		Subject: "subj", ContentType: "text/html", TimeOut: time.Millisecond * 100}
	e := NewEmailClient(p, capturing)
	_ = e.Send("victim@example.com", secretBody) // expected to fail (no smtp server) — we only assert the log

	logged := buf.String()
	assert.NotContains(t, logged, secretBody, "email body must not appear in logs")
	assert.NotContains(t, logged, "super-secret-magic-link-XYZ", "any substring of the body must not appear in logs")
	assert.Contains(t, logged, "victim@example.com", "recipient is safe to log")
}

func TestEmail_SendFailed(t *testing.T) {
	p := EmailParams{Host: "127.0.0.2", Port: 25, From: "from@example.com",
		Subject: "subj", ContentType: "text/html", TimeOut: time.Millisecond * 200}
	e := NewEmailClient(p, logger.Std)
	assert.Equal(t, p, e.EmailParams)
	err := e.Send("to@example.com", "some text")
	require.NotNil(t, err, "failed to make smtp client")

	p = EmailParams{Host: "127.0.0.1", Port: 225, From: "from@example.com", Subject: "subj", ContentType: "text/html",
		TLS: true}
	e = NewEmailClient(p, logger.Std)
	err = e.Send("to@example.com", "some text")
	require.NotNil(t, err)
}

// fakeSMTP accepts one connection, speaks the minimum needed to reach DATA and
// returns the greeting line the client sent.
func fakeSMTP(t *testing.T) (addr string, greeting <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan string, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		writeLine := func(s string) {
			_, _ = w.WriteString(s + "\r\n")
			_ = w.Flush()
		}

		writeLine("220 fake ESMTP")
		for {
			line, e := r.ReadString('\n')
			if e != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				select {
				case got <- strings.TrimSpace(line):
				default:
				}
				writeLine("250-fake greets you")
				writeLine("250 HELP")
			case strings.HasPrefix(cmd, "QUIT"):
				writeLine("221 bye")
				return
			case strings.HasPrefix(cmd, "DATA"):
				writeLine("354 go ahead")
			case cmd == ".":
				writeLine("250 queued")
			default:
				writeLine("250 ok")
			}
		}
	}()

	return ln.Addr().String(), got
}

func TestEmail_HELOHost(t *testing.T) {
	tbl := []struct {
		name     string
		heloHost string
		want     string
	}{
		{"configured host is announced", "mail.example.com", "mail.example.com"},
		{"unset keeps the previous localhost greeting", "", "localhost"},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			addr, greeting := fakeSMTP(t)
			host, portStr, err := net.SplitHostPort(addr)
			require.NoError(t, err)
			port, err := strconv.Atoi(portStr)
			require.NoError(t, err)

			client := NewEmailClient(EmailParams{
				Host: host, Port: port, From: "from@example.com",
				Subject: "subj", HELOHost: tt.heloHost, TimeOut: 5 * time.Second,
			}, logger.Std)

			_ = client.Send("to@example.com", "body")

			select {
			case line := <-greeting:
				assert.Equal(t, "EHLO "+tt.want, line)
			case <-time.After(5 * time.Second):
				t.Fatal("no greeting received")
			}
		})
	}
}
