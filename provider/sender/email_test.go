package sender

import (
	"bytes"
	"io"
	"net/smtp"
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
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

func TestEmail_buildMessage(t *testing.T) {
	p := EmailParams{From: "from@example.com", Subject: "subj"}
	e := Email{L: logger.Std, EmailParams: p}

	msg, err := e.buildMessage("this is a test\n12345\n", "to@example.com")
	require.NoError(t, err)
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example.com\nSubject: subj\n", msg)
	assert.Contains(t, msg, "this is a test\r\n12345", msg)
	assert.Contains(t, msg, "Date: ", msg)
	assert.Contains(t, msg, "Content-Transfer-Encoding: quoted-printable", msg)
}

func TestEmail_buildMessageWithMIME(t *testing.T) {

	p := EmailParams{From: "from@example.com", Subject: "subj", ContentType: "text/html"}
	e := Email{L: logger.Std, EmailParams: p}

	msg, err := e.buildMessage("this is a test\n12345\n", "to@example.com")
	require.NoError(t, err)
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example.com\nSubject: subj\nContent-Transfer-Encoding: quoted-printable\nMIME-version: 1.0\nContent-Type: text/html; charset=\"UTF-8\"", msg)
	assert.Contains(t, msg, "\n\nthis is a test\r\n12345", msg)
	assert.Contains(t, msg, "Date: ", msg)
}

func TestEmail_New(t *testing.T) {
	p := EmailParams{Host: "127.0.0.2", From: "from@example.com", Subject: "subj", ContentType: "text/html"}
	e := NewEmailClient(p, logger.Std)
	assert.Equal(t, p, e.EmailParams)
}

func TestEmail_Send(t *testing.T) {
	fakeSMTP := &fakeTestSMTP{}
	p := EmailParams{From: "from@example.com", Subject: "subj", ContentType: "text/html",
		SMTPUserName: "user", SMTPPassword: "passwd"}
	e := Email{L: logger.Std, EmailParams: p, SMTPClient: fakeSMTP}
	err := e.Send("to@example.com", "some text\n")
	require.NoError(t, err)

	assert.Equal(t, "from@example.com", fakeSMTP.mail)
	assert.Equal(t, "to@example.com", fakeSMTP.rcpt)
	msg := fakeSMTP.buff.String()
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example."+
		"com\nSubject: subj\nContent-Transfer-Encoding: quoted-printable\nMIME-version: 1."+
		"0\nContent-Type: text/html; charset=\"UTF-8\"", msg)
	assert.Contains(t, msg, "\n\nsome text", msg)
	assert.Contains(t, msg, "Date: ", msg)

	assert.True(t, fakeSMTP.auth)
	assert.True(t, fakeSMTP.quit)
	assert.False(t, fakeSMTP.close)
}

func TestEmail_SendFailed(t *testing.T) {
	fakeSMTP := &fakeTestSMTP{fail: true}
	p := EmailParams{From: "from@example.com", Subject: "subj", ContentType: "text/html"}
	e := Email{L: logger.Std, EmailParams: p, SMTPClient: fakeSMTP}
	err := e.Send("to@example.com", "some text")
	require.EqualError(t, err, "can't make email writer: failed")

	assert.Equal(t, "from@example.com", fakeSMTP.mail)
	assert.Equal(t, "to@example.com", fakeSMTP.rcpt)
	assert.Equal(t, "", fakeSMTP.buff.String())
	assert.False(t, fakeSMTP.auth)
	assert.False(t, fakeSMTP.quit)
	assert.True(t, fakeSMTP.close)
}

func TestEmail_SendFailed2(t *testing.T) {
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

type fakeTestSMTP struct {
	fail bool

	buff        bytes.Buffer
	mail, rcpt  string
	auth        bool
	quit, close bool
}

func (f *fakeTestSMTP) Mail(m string) error  { f.mail = m; return nil }
func (f *fakeTestSMTP) Auth(smtp.Auth) error { f.auth = true; return nil }
func (f *fakeTestSMTP) Rcpt(r string) error  { f.rcpt = r; return nil }
func (f *fakeTestSMTP) Quit() error          { f.quit = true; return nil }
func (f *fakeTestSMTP) Close() error         { f.close = true; return nil }

func (f *fakeTestSMTP) Data() (io.WriteCloser, error) {
	if f.fail {
		return nil, errors.New("failed")
	}
	return nopCloser{&f.buff}, nil
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }
