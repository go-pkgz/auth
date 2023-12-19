package sender

import (
	"os"
	"testing"
	"time"

	"github.com/go-pkgz/auth/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
