package sender

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"

	"github.com/pkg/errors"

	"github.com/go-pkgz/auth/logger"
)

type Email struct {
	logger.L

	Host        string
	Port        int
	From        string
	Subject     string
	ContentType string

	TLS          bool
	SMTPUserName string
	SMTPPassword string
}

func (e *Email) Send(to string, text string) error {

	c, err := e.client()
	if err != nil {
		return errors.Wrap(err, "failed to make smtp client")
	}
	var quit bool
	defer func() {
		if quit {
			return
		}
		if err = c.Close(); err != nil {
			e.Logf("[WARN] can't close smtp connection, %v", err)
		}
	}()

	if e.SMTPUserName != "" && e.SMTPPassword != "" {
		auth := smtp.PlainAuth("", e.SMTPUserName, e.SMTPPassword, e.Host)
		if err = c.Auth(auth); err != nil {
			return errors.Wrapf(err, "failed to auth to smtp %s:%d", e.Host, e.Port)
		}
	}

	if err = c.Mail(e.From); err != nil {
		return errors.Wrapf(err, "bad from address %q", e.From)
	}
	if err = c.Rcpt(to); err != nil {
		return errors.Wrapf(err, "bad to address %q", to)
	}

	writer, err := c.Data()
	if err != nil {
		return errors.Wrap(err, "can't make email writer")
	}

	buf := bytes.NewBufferString(e.buildMessage(text, to))
	if _, err = buf.WriteTo(writer); err != nil {
		return errors.Wrapf(err, "failed to send email body to %q", to)
	}
	if err = writer.Close(); err != nil {
		e.Logf("[WARN] can't close smtp body writer, %v", err)
	}

	if err = c.Quit(); err != nil {
		e.Logf("[WARN] failed to send quit command to %s:%d, %v", e.Host, e.Port, err)
	}
	quit = true
	return nil
}

func (e *Email) client() (c *smtp.Client, err error) {
	srvAddress := fmt.Sprintf("%s:%d", e.Host, e.Port)
	if e.TLS {
		tlsConf := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         e.Host,
		}
		conn, err := tls.Dial("tcp", srvAddress, tlsConf)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to dial smtp tls to %s", srvAddress)
		}
		if c, err = smtp.NewClient(conn, e.Host); err != nil {
			return nil, errors.Wrapf(err, "failed to make smtp client for %s", srvAddress)
		}
		return c, nil
	}

	c, err = smtp.Dial(srvAddress)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial")
	}
	return c, nil
}

func (e *Email) buildMessage(msg string, to string) (message string) {
	message += fmt.Sprintf("From: %s\n", e.From)
	message += fmt.Sprintf("To: %s\n", to)
	message += fmt.Sprintf("Subject: %s\n", e.Subject)
	if e.ContentType != "" {
		message += fmt.Sprintf("MIME-version: 1.0;\nContent-Type: %s; charset=\"UTF-8\";\n", e.ContentType)
	}
	message += "\n" + msg
	return message
}
