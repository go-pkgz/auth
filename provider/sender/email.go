package sender

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"time"

	"github.com/pkg/errors"

	"github.com/go-pkgz/auth/logger"
)

// Email implements sender interface for VerifyHandler
// Uses common subject line and "from" for all messages
type Email struct {
	logger.L
	SMTPClient
	EmailParams
}

// EmailParams  with all needed to make new Email client with smtp
type EmailParams struct {
	Host        string // SMTP host
	Port        int    // SMTP port
	From        string // From email field
	Subject     string // Email subject
	ContentType string // Content type, optional. Will trigger MIME and Content-Type headers

	TLS          bool   // TLS auth
	SMTPUserName string // user name
	SMTPPassword string // password
	TimeOut      time.Duration
}

// SMTPClient interface defines subset of net/smtp used by email client
type SMTPClient interface {
	Mail(string) error
	Auth(smtp.Auth) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}

// NewEmailClient creates email client with prepared smtp
func NewEmailClient(p EmailParams, l logger.L) *Email {
	return &Email{EmailParams: p, L: l, SMTPClient: nil}
}

// Send email with given text
// If SMTPClient defined in Email struct it will be used, if not - new smtp.Client on each send.
// Always closes client on completion or failure.
func (em *Email) Send(to string, text string) error {

	client := em.SMTPClient
	if client == nil { // if client not set make new net/smtp
		c, err := em.client()
		if err != nil {
			return errors.Wrap(err, "failed to make smtp client")
		}
		client = c
	}

	var quit bool
	defer func() {
		if quit { // quit set if Quit() call passed because it's closing connection as well.
			return
		}
		if err := client.Close(); err != nil {
			em.Logf("[WARN] can't close smtp connection, %v", err)
		}
	}()

	if em.SMTPUserName != "" && em.SMTPPassword != "" {
		auth := smtp.PlainAuth("", em.SMTPUserName, em.SMTPPassword, em.Host)
		if err := client.Auth(auth); err != nil {
			return errors.Wrapf(err, "failed to auth to smtp %s:%d", em.Host, em.Port)
		}
	}

	if err := client.Mail(em.From); err != nil {
		return errors.Wrapf(err, "bad from address %q", em.From)
	}
	if err := client.Rcpt(to); err != nil {
		return errors.Wrapf(err, "bad to address %q", to)
	}

	writer, err := client.Data()
	if err != nil {
		return errors.Wrap(err, "can't make email writer")
	}

	buf := bytes.NewBufferString(em.buildMessage(text, to))
	if _, err = buf.WriteTo(writer); err != nil {
		return errors.Wrapf(err, "failed to send email body to %q", to)
	}
	if err = writer.Close(); err != nil {
		em.Logf("[WARN] can't close smtp body writer, %v", err)
	}

	if err = client.Quit(); err != nil {
		em.Logf("[WARN] failed to send quit command to %s:%d, %v", em.Host, em.Port, err)
	} else {
		quit = true
	}
	return nil
}

func (em *Email) client() (c *smtp.Client, err error) {
	srvAddress := fmt.Sprintf("%s:%d", em.Host, em.Port)
	if em.TLS {
		tlsConf := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         em.Host,
		}
		conn, err := tls.Dial("tcp", srvAddress, tlsConf)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to dial smtp tls to %s", srvAddress)
		}
		if c, err = smtp.NewClient(conn, em.Host); err != nil {
			return nil, errors.Wrapf(err, "failed to make smtp client for %s", srvAddress)
		}
		return c, nil
	}

	conn, err := net.DialTimeout("tcp", srvAddress, em.TimeOut)
	if err != nil {
		return nil, errors.Wrapf(err, "timeout connecting to %s", srvAddress)
	}

	c, err = smtp.NewClient(conn, srvAddress)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial")
	}
	return c, nil
}

func (em *Email) buildMessage(msg string, to string) (message string) {
	message += fmt.Sprintf("From: %s\n", em.From)
	message += fmt.Sprintf("To: %s\n", to)
	message += fmt.Sprintf("Subject: %s\n", em.Subject)
	if em.ContentType != "" {
		message += fmt.Sprintf("MIME-version: 1.0;\nContent-Type: %s; charset=\"UTF-8\";\n", em.ContentType)
	}
	message += "\n" + msg
	return message
}
