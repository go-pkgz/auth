package email

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/email/mocks"
)

func TestEmail_New(t *testing.T) {
	logBuff := bytes.NewBuffer(nil)
	logger := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(logBuff, format, args...)
	}}

	s := NewSender("localhost", ContentType("text/html"), Port(123),
		TLS(true), STARTTLS(true), InsecureSkipVerify(true), Auth("user", "pass"), TimeOut(time.Second),
		Log(logger), Charset("blah"),
	)
	require.NotNil(t, s)
	assert.Equal(t, "[INFO] new email sender created with host: localhost:123, helo: \"localhost\", tls: true, insecureSkipVerify: true, username: \"user\", timeout: 1s, content type: \"text/html\", charset: \"blah\"",
		logBuff.String())

	assert.Equal(t, "localhost", s.host)
	assert.Equal(t, 123, s.port)
	assert.Equal(t, "user", s.smtpUserName)
	assert.Equal(t, "pass", s.smtpPassword)
	assert.Equal(t, authMethodPlain, s.authMethod)
	assert.Equal(t, time.Second, s.timeOut)
	assert.Equal(t, "text/html", s.contentType)
	assert.Equal(t, "blah", s.contentCharset)
	assert.Empty(t, s.heloHost)
	assert.True(t, s.tls)
	assert.True(t, s.starttls)
}

func TestEmail_NewHELOHost(t *testing.T) {
	tests := []struct {
		name          string
		options       []Option
		wantStored    string
		wantEffective string
	}{
		{name: "unset greets as localhost", wantEffective: "localhost"},
		{name: "explicit empty greets as localhost", options: []Option{HELOHost("")}, wantEffective: "localhost"},
		{name: "explicit hostname", options: []Option{HELOHost("client.example.net")}, wantStored: "client.example.net", wantEffective: "client.example.net"},
		{name: "explicit localhost", options: []Option{HELOHost("localhost")}, wantStored: "localhost", wantEffective: "localhost"},
		{name: "address literal", options: []Option{HELOHost("[192.0.2.10]")}, wantStored: "[192.0.2.10]", wantEffective: "[192.0.2.10]"},
		{name: "injected client owns greeting", options: []Option{SMTP(&mocks.SMTPClientMock{}), HELOHost("ignored.example.net")}, wantStored: "ignored.example.net", wantEffective: "client-managed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSender("localhost", tt.options...)
			assert.Equal(t, tt.wantStored, s.heloHost)
			assert.Equal(t, tt.wantEffective, s.effectiveHELOHost())
		})
	}
}

func TestEmail_ClientHELOHost(t *testing.T) {
	tests := []struct {
		name    string
		sender  func(host string, port int) *Sender
		wantCmd string
	}{
		{
			name: "explicit address literal",
			sender: func(host string, port int) *Sender {
				return NewSender(host, Port(port), HELOHost("[192.0.2.10]"))
			},
			wantCmd: "EHLO [192.0.2.10]",
		},
		{
			name: "explicit hostname",
			sender: func(host string, port int) *Sender {
				return NewSender(host, Port(port), HELOHost("client.example.net"))
			},
			wantCmd: "EHLO client.example.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
				if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
					return err
				}
				reader := bufio.NewReader(conn)
				cmd, err := readSMTPCommand(reader)
				if err != nil {
					return err
				}
				if cmd != tt.wantCmd {
					return fmt.Errorf("unexpected greeting %q, want %q", cmd, tt.wantCmd)
				}
				if writeErr := writeSMTPResponse(conn, "250 smtp.example.net"); writeErr != nil {
					return writeErr
				}
				return expectSMTPQuit(conn, reader)
			})

			client, _, err := tt.sender(host, port).client(context.Background())
			require.NoError(t, err)
			require.NoError(t, client.Quit())
			waitSMTPTestServer(t, done)
		})
	}
}

// pins backward compatibility: a caller setting no HELOHost must greet exactly as before the option existed
func TestEmail_ClientWithoutHELOHostGreetsLocalhost(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO localhost" {
			return fmt.Errorf("unexpected greeting %q", cmd)
		}
		if writeErr := writeSMTPResponse(conn, "250 smtp.example.net"); writeErr != nil {
			return writeErr
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "MAIL FROM:<sender@example.com>" {
			return fmt.Errorf("unexpected mail command %q", cmd)
		}
		if err := writeSMTPResponse(conn, "250 sender accepted"); err != nil {
			return err
		}
		return expectSMTPQuit(conn, reader)
	})

	client, _, err := NewSender(host, Port(port)).client(context.Background())
	require.NoError(t, err)
	require.NoError(t, client.Mail("sender@example.com"))
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientHELOFallback(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected EHLO command %q", cmd)
		}
		if writeErr := writeSMTPResponse(conn, "500 EHLO unavailable"); writeErr != nil {
			return writeErr
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "HELO client.example.net" {
			return fmt.Errorf("unexpected HELO command %q", cmd)
		}
		if err := writeSMTPResponse(conn, "250 smtp.example.net"); err != nil {
			return err
		}
		return expectSMTPQuit(conn, reader)
	})

	sender := NewSender(host, Port(port), HELOHost("client.example.net"))
	client, _, err := sender.client(context.Background())
	require.NoError(t, err)
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientHELOFailureClosesConnection(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		if _, err := readSMTPCommand(reader); err != nil {
			return err
		}
		if err := writeSMTPResponse(conn, "500 EHLO unavailable"); err != nil {
			return err
		}
		if _, err := readSMTPCommand(reader); err != nil {
			return err
		}
		if err := writeSMTPResponse(conn, "550 HELO rejected"); err != nil {
			return err
		}
		return expectSMTPConnectionClosed(conn, reader)
	})

	sender := NewSender(host, Port(port), HELOHost("client.example.net"))
	client, _, err := sender.client(context.Background())
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to send SMTP greeting")
	assert.Contains(t, err.Error(), "550")
	assert.Contains(t, err.Error(), "HELO rejected")
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientSTARTTLSFailureClosesConnection(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting %q", cmd)
		}
		if _, err = io.WriteString(conn, "250-smtp.example.net\r\n250 STARTTLS\r\n"); err != nil {
			return err
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "STARTTLS" {
			return fmt.Errorf("unexpected command %q", cmd)
		}
		if err := writeSMTPResponse(conn, "454 TLS unavailable"); err != nil {
			return err
		}
		return expectSMTPConnectionClosed(conn, reader)
	})

	sender := NewSender(host, Port(port), STARTTLS(true), HELOHost("client.example.net"))
	client, _, err := sender.client(context.Background())
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to start tls")
	assert.Contains(t, err.Error(), "454")
	assert.Contains(t, err.Error(), "TLS unavailable")
	waitSMTPTestServer(t, done)
}

func TestEmail_SendRejectedAfterData(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		for _, response := range []string{"250 smtp.example.net", "250 sender accepted", "250 recipient accepted", "354 send the message"} {
			if _, err := readSMTPCommand(reader); err != nil {
				return err
			}
			if err := writeSMTPResponse(conn, response); err != nil {
				return err
			}
		}

		for { // read the message until the terminating dot
			line, err := readSMTPCommand(reader)
			if err != nil {
				return err
			}
			if line == "." {
				break
			}
		}
		return writeSMTPResponse(conn, "552 message rejected")
	})

	sender := NewSender(host, Port(port), ContentType("text/html"), TimeOut(3*time.Second))
	err := sender.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.Error(t, err, "rejection of the message by the server has to reach the caller")
	assert.Contains(t, err.Error(), "552")
	assert.Contains(t, err.Error(), "message rejected")
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientSTARTTLSReusesHELOHost(t *testing.T) {
	serverTLS := smtpTestTLSConfig(t)
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting before STARTTLS %q", cmd)
		}
		if _, err = io.WriteString(conn, "250-smtp.example.net\r\n250 STARTTLS\r\n"); err != nil {
			return err
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "STARTTLS" {
			return fmt.Errorf("unexpected command %q", cmd)
		}
		if writeErr := writeSMTPResponse(conn, "220 ready for TLS"); writeErr != nil {
			return writeErr
		}

		tlsConn := tls.Server(conn, serverTLS)
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			return handshakeErr
		}
		reader = bufio.NewReader(tlsConn)
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting after STARTTLS %q", cmd)
		}
		if err := writeSMTPResponse(tlsConn, "250 smtp.example.net"); err != nil {
			return err
		}
		return expectSMTPQuit(tlsConn, reader)
	})

	sender := NewSender(host, Port(port), STARTTLS(true), InsecureSkipVerify(true), HELOHost("client.example.net"))
	client, _, err := sender.client(context.Background())
	require.NoError(t, err)
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientTLSHELOHost(t *testing.T) {
	serverTLS := smtpTestTLSConfig(t)
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		tlsConn := tls.Server(conn, serverTLS)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		if err := writeSMTPResponse(tlsConn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(tlsConn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting %q", cmd)
		}
		if err := writeSMTPResponse(tlsConn, "250 smtp.example.net"); err != nil {
			return err
		}
		return expectSMTPQuit(tlsConn, reader)
	})

	sender := NewSender(host, Port(port), TLS(true), InsecureSkipVerify(true), HELOHost("client.example.net"))
	client, _, err := sender.client(context.Background())
	require.NoError(t, err)
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_Send(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"), TimeOut(time.Second), HELOHost("ignored.example.net"))

	s.timeNow = func() time.Time { return time.Date(2022, time.February, 10, 23, 33, 58, 0, time.UTC) }

	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)

	expBody := "From: from@example.com\nTo: to@example.com\nSubject: subj\nMIME-version: 1.0\nDate: Thu, 10 Feb 2022 23:33:58 +0000\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"\n\nsome text\r\n"
	assert.Equal(t, expBody, wc.buff.String())

	require.Len(t, smtpClient.MailCalls(), 1)
	assert.Equal(t, "from@example.com", smtpClient.MailCalls()[0].From)

	require.Len(t, smtpClient.RcptCalls(), 1)
	assert.Equal(t, "to@example.com", smtpClient.RcptCalls()[0].To)

	assert.Len(t, smtpClient.AuthCalls(), 1)
	assert.Len(t, smtpClient.QuitCalls(), 1)
	assert.Len(t, smtpClient.DataCalls(), 1)

	assert.Empty(t, smtpClient.CloseCalls(), "not called because quit is called")
}

func TestEmail_SendWithDisplayName(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"), TimeOut(time.Second))

	s.timeNow = func() time.Time { return time.Date(2022, time.February, 10, 23, 33, 58, 0, time.UTC) }

	err := s.Send("some text\n", Params{
		From:    `"John Doe" <john@example.com>`,
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)

	expBody := "From: \"John Doe\" <john@example.com>\nTo: to@example.com\nSubject: subj\nMIME-version: 1.0\nDate: Thu, 10 Feb 2022 23:33:58 +0000\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"\n\nsome text\r\n"
	assert.Equal(t, expBody, wc.buff.String())
	assert.Equal(t, "john@example.com", smtpClient.MailCalls()[0].From)
}

func TestEmail_LoginAuth(t *testing.T) {
	s := NewSender("localhost", Auth("user", "pass"), LoginAuth())
	auth := s.auth()
	proto, _, err := auth.Start(&smtp.ServerInfo{Name: "localhost"})

	require.NoError(t, err)
	assert.Equal(t, "LOGIN", proto)
}

func TestEmail_SendFailedAuth(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return errors.New("auth error") },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.EqualError(t, err, "failed to auth to smtp localhost:25, auth error")
	assert.Len(t, smtpClient.AuthCalls(), 1)
	assert.Empty(t, smtpClient.QuitCalls())
	assert.Len(t, smtpClient.CloseCalls(), 1, "called because quit is not called before")
}

func TestEmail_SendFailedQUIT(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return errors.New("quit error") },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Len(t, smtpClient.QuitCalls(), 1)
	assert.Len(t, smtpClient.CloseCalls(), 1)
}

func TestEmail_SendFailedCLOSE(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return errors.New("close error") },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return errors.New("quit error") },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Len(t, smtpClient.QuitCalls(), 1)
	assert.Len(t, smtpClient.CloseCalls(), 1)
}

func TestEmail_SendFailedRCPTO(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return errors.New("RCPT error") },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.EqualError(t, err, "bad to address [\"to@example.com\"]: RCPT error")
	assert.Len(t, smtpClient.RcptCalls(), 1)
}

func TestEmail_SendFailedMakeClient(t *testing.T) {
	{
		s := NewSender("198.18.0.254", Port(12345), TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err, "failed to make smtp client")
		assert.Contains(t, err.Error(), "i/o timeout")
	}

	{
		s := NewSender("198.18.0.254", Port(225), TLS(true), TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err, "failed to make smtp client")
		assert.Contains(t, err.Error(), "i/o timeout")
	}
}

func TestEmail_SendFailed(t *testing.T) {

	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil), fail: true}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.EqualError(t, err, "failed to send email body to [\"to@example.com\"]: write error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return errors.New("mail error") },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.EqualError(t, err, "bad from address \"from@example.com\": mail error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, errors.New("data error") },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.EqualError(t, err, "can't make email writer: data error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{},
			Subject: "subj",
		})
		require.EqualError(t, err, "no recipients")
		assert.Len(t, smtpClient.CloseCalls(), 1, "client set with the SMTP option is closed on every failure")
	}
}

func TestEmail_SendRejectedBody(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil), closeErr: errors.New("552 5.3.4 message too big")}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.EqualError(t, err, "failed to send email to [\"to@example.com\"]: 552 5.3.4 message too big")
	assert.True(t, wc.closed)
	assert.Empty(t, smtpClient.QuitCalls(), "no quit for a message the server didn't accept")
	assert.Len(t, smtpClient.CloseCalls(), 1, "connection closed by the deferred cleanup")
}

func TestEmail_SendHeaderInjection(t *testing.T) {
	injected := "victim@example.net (x\r\nSubject: Security notice\r\nContent-Type: text/html\r\n\r\n<a href=\"https://attacker.example/\">click</a>"

	tests := []struct {
		name   string
		params Params
		expErr string
	}{
		{
			name:   "CRLF in recipient",
			params: Params{From: "from@example.com", To: []string{injected}, Subject: "subj"},
			expErr: "invalid To header value",
		},
		{
			name:   "CRLF in one of the recipients",
			params: Params{From: "from@example.com", To: []string{"to@example.com", injected}, Subject: "subj"},
			expErr: "invalid To header value",
		},
		{
			name:   "CRLF in sender",
			params: Params{From: "from@example.com\r\nBcc: attacker@example.net", To: []string{"to@example.com"}},
			expErr: "invalid From header value",
		},
		{
			name:   "CRLF in subject",
			params: Params{From: "from@example.com", To: []string{"to@example.com"}, Subject: "subj\r\nBcc: attacker@example.net"},
			expErr: "invalid Subject header value",
		},
		{
			name: "CRLF in unsubscribe link",
			params: Params{From: "from@example.com", To: []string{"to@example.com"}, Subject: "subj",
				UnsubscribeLink: "https://example.com/unsubscribe>\r\nBcc: attacker@example.net"},
			expErr: "invalid List-Unsubscribe header value",
		},
		{
			name: "LF in in-reply-to",
			params: Params{From: "from@example.com", To: []string{"to@example.com"}, Subject: "subj",
				InReplyTo: "uuid@example.com>\nBcc: attacker@example.net"},
			expErr: "invalid In-reply-to header value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
			smtpClient := &mocks.SMTPClientMock{
				AuthFunc:  func(_ smtp.Auth) error { return nil },
				CloseFunc: func() error { return nil },
				MailFunc:  func(string) error { return nil },
				QuitFunc:  func() error { return nil },
				RcptFunc:  func(_ string) error { return nil },
				DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
			}

			s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
			err := s.Send("some text\n", tt.params)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expErr)

			assert.Empty(t, smtpClient.MailCalls(), "rejected before talking to the server")
			assert.Empty(t, smtpClient.RcptCalls())
			assert.Empty(t, smtpClient.DataCalls())
			assert.Empty(t, wc.buff.String(), "nothing sent")
			assert.Len(t, smtpClient.CloseCalls(), 1, "client set with the SMTP option is closed on every failure")
		})
	}
}

func TestEmail_SendNoDataOnBadMessage(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "subj",
		Attachments: []string{"does/not/exist/1.txt"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "can't make email message")
	assert.Empty(t, smtpClient.DataCalls(), "message is built before the data command")
	assert.Empty(t, smtpClient.MailCalls())
	assert.Len(t, smtpClient.CloseCalls(), 1, "client set with the SMTP option is closed on every failure")
}

func TestEmail_buildMessage(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}
	e := NewSender("localhost", Log(l))
	msg, err := e.buildMessage("this is a test\n12345\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com", "to2@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Contains(t, msg.String(), "From: from@example.com\nTo: to@example.com,to2@example.com\nSubject: subj\n", msg.String())
	assert.Contains(t, msg.String(), "this is a test\r\n12345", msg.String())
	assert.Contains(t, msg.String(), "Date: ", msg.String())
	assert.Contains(t, msg.String(), "Content-Transfer-Encoding: quoted-printable", msg.String())

	tree := parseMIMETree(t, msg.String())
	assert.Equal(t, "text/plain", tree.mediaType)
	assert.Empty(t, tree.children)
}

func TestEmail_buildMessageWithMIME(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))

	msg, err := e.buildMessage("this is a test\n12345\n", Params{
		From:            "from@example.com",
		To:              []string{"to@example.com"},
		Subject:         "non-ascii symbols: Привет",
		UnsubscribeLink: "https://example.com/unsubscribe",
		InReplyTo:       "uuid@example.com",
	})
	require.NoError(t, err)
	assert.Contains(t, msg.String(), "Content-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"", msg.String())
	assert.Contains(t, msg.String(), "From: from@example.com\nTo: to@example.com\nSubject: =?utf-8?b?bm9uLWFzY2lpIHN5bWJvbHM6INCf0YDQuNCy0LXRgg==?=\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\nList-Unsubscribe: <https://example.com/unsubscribe>\nIn-reply-to: <uuid@example.com>\nMIME-version: 1.0", msg.String())
	assert.Contains(t, msg.String(), "\n\nthis is a test\r\n12345\r\n", msg.String())
	assert.Contains(t, msg.String(), "Date: ", msg.String())
}

func TestEmail_buildMessageWithMIMEAndAttachments(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with attachments\\n12345</div>\\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"},
	})
	require.NoError(t, err)
	tree := parseMIMETree(t, msg.String())
	require.Equal(t, "multipart/mixed", tree.mediaType)
	body, ok := tree.firstChild("text/html")
	require.True(t, ok, "html body part present under mixed")
	assert.Empty(t, body.disposition)
	attachments := tree.childrenByDisposition("attachment")
	require.Len(t, attachments, 3)
	assert.Equal(t, []string{"1.txt", "2.txt", "image.jpg"}, attachmentNames(tree.childrenByDisposition("attachment")))

	fData1, err := os.ReadFile("testdata/1.txt")
	require.NoError(t, err)
	fData2, err := os.ReadFile("testdata/2.txt")
	require.NoError(t, err)
	fData3, err := os.ReadFile("testdata/image.jpg")
	require.NoError(t, err)
	assert.Equal(t, fData1, attachments[0].content, "1.txt decodes back to the file content")
	assert.Equal(t, fData2, attachments[1].content, "2.txt decodes back to the file content")
	assert.Equal(t, fData3, attachments[2].content, "image.jpg decodes back to the file content")
}

func TestEmail_buildMessageWithMIMEAndWrongAttachments(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with attachments\\n12345</div>\\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/1.txt", "testdata/2.txt", "does/not/exist/1.txt"},
	})
	require.Error(t, err)
	require.Equal(t, "failed to write attachments: "+
		"open does/not/exist/1.txt: no such file or directory", err.Error())
	require.Nil(t, msg)

}

func TestEmail_buildMessageWithEmptyAttachment(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))

	msg, err := e.buildMessage("<div>this is a test mail with an empty attachment</div>", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/nullfile", "testdata/1.txt"},
	})
	require.NoError(t, err, "an empty file is a valid attachment")
	assert.Contains(t, msg.String(), "Content-Disposition: attachment; filename=nullfile", msg.String())

	tree := parseMIMETree(t, msg.String())
	attachments := tree.childrenByDisposition("attachment")
	require.Len(t, attachments, 2)
	assert.Empty(t, attachments[0].content, "the empty file makes an empty part")
	assert.Equal(t, "text/plain", attachments[0].mediaType)

	fData, err := os.ReadFile("testdata/1.txt")
	require.NoError(t, err)
	assert.Equal(t, fData, attachments[1].content, "the attachment after the empty one is intact")
}

func TestEmail_buildMessageWithMIMEAndInlineImages(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with inline images</div><div><img src=\"cid:image.jpg\"></div>\n", Params{
		From:         "from@example.com",
		To:           []string{"to@example.com"},
		Subject:      "test email with attachments",
		InlineImages: []string{"testdata/image.jpg"},
	})
	require.NoError(t, err)
	assert.Contains(t, msg.String(), "MIME-version: 1.0", msg.String())
	tree := parseMIMETree(t, msg.String())
	require.Equal(t, "multipart/related", tree.mediaType)
	body, ok := tree.firstChild("text/html")
	require.True(t, ok, "html body part present under related")
	assert.Empty(t, body.disposition)
	img, ok := tree.firstChild("image/jpeg")
	require.True(t, ok, "inline image part present under related")
	assert.Equal(t, "inline", img.disposition)
	assert.Equal(t, "<image.jpg>", img.contentID)
	assert.Equal(t, []string{"image.jpg"}, attachmentNames(tree.childrenByDisposition("inline")))
	assert.Contains(t, msg.String(), "Content-Id: <image.jpg>", msg.String())
	assert.Contains(t, msg.String(), "Content-Transfer-Encoding: base64", msg.String())
	fData, err := os.ReadFile("testdata/image.jpg")
	require.NoError(t, err)
	assert.Equal(t, fData, img.content, "inline image decodes back to the file content")
}

func TestEmail_buildMessageWithMIMEAndAttachmentsAndInlineImages(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with inline images</div><div><img src=\"cid:image.jpg\"></div>\n", Params{
		From:         "from@example.com",
		To:           []string{"to@example.com"},
		Subject:      "test email with attachments",
		Attachments:  []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"},
		InlineImages: []string{"testdata/image.jpg"},
	})
	require.NoError(t, err)
	assert.Contains(t, msg.String(), "MIME-version: 1.0", msg.String())
	tree := parseMIMETree(t, msg.String())
	require.Equal(t, "multipart/mixed", tree.mediaType)
	related, ok := tree.firstChild("multipart/related")
	require.True(t, ok, "related subtree present under mixed")
	htmlBody, ok := related.firstChild("text/html")
	require.True(t, ok, "html body inside related")
	assert.Empty(t, htmlBody.disposition)
	img, ok := related.firstChild("image/jpeg")
	require.True(t, ok, "inline image inside related, not directly under mixed")
	require.Len(t, related.childrenByDisposition("inline"), 1)
	assert.Equal(t, "inline", img.disposition)
	assert.Equal(t, "<image.jpg>", img.contentID)
	attachments := tree.childrenByDisposition("attachment")
	require.Len(t, attachments, 3)
	assert.Equal(t, []string{"1.txt", "2.txt", "image.jpg"}, attachmentNames(tree.childrenByDisposition("attachment")))
	assert.Equal(t, []string{"image.jpg"}, attachmentNames(related.childrenByDisposition("inline")))
	assert.Contains(t, msg.String(), "Content-Id: <image.jpg>", msg.String())
	assert.Contains(t, msg.String(), "Content-Transfer-Encoding: base64", msg.String())

	fData1, err := os.ReadFile("testdata/1.txt")
	require.NoError(t, err)
	fData2, err := os.ReadFile("testdata/2.txt")
	require.NoError(t, err)
	fData3, err := os.ReadFile("testdata/image.jpg")
	require.NoError(t, err)
	assert.Equal(t, fData1, attachments[0].content, "1.txt decodes back to the file content")
	assert.Equal(t, fData2, attachments[1].content, "2.txt decodes back to the file content")
	assert.Equal(t, fData3, attachments[2].content, "image.jpg decodes back to the file content")
}

func TestEmail_buildMessageFileNameInjection(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))
	dir := t.TempDir()

	write := func(t *testing.T, name string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("attachment body"), 0o600))
		return path
	}

	t.Run("CRLF in the file name is rejected", func(t *testing.T) {
		path := write(t, "invoice.pdf\"\r\nX-Injected: yes\r\n\r\ninjected body\r\n")

		msg, err := e.buildMessage("body", Params{
			From:        "from@example.com",
			To:          []string{"to@example.com"},
			Subject:     "subj",
			Attachments: []string{path},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contains CR or LF")
		require.Nil(t, msg)
	})

	t.Run("CRLF in an inline image name is rejected", func(t *testing.T) {
		path := write(t, "img.jpg\r\nContent-ID: <spoofed>\r\n")

		msg, err := e.buildMessage("body", Params{
			From:         "from@example.com",
			To:           []string{"to@example.com"},
			Subject:      "subj",
			InlineImages: []string{path},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contains CR or LF")
		require.Nil(t, msg)
	})

	t.Run("quotes, spaces and non-ascii survive intact", func(t *testing.T) {
		names := []string{`in"voice pdf.txt`, "счёт.txt", "semi;colon.txt"}
		paths := make([]string, 0, len(names))
		for _, name := range names {
			paths = append(paths, write(t, name))
		}

		msg, err := e.buildMessage("body", Params{
			From:        "from@example.com",
			To:          []string{"to@example.com"},
			Subject:     "subj",
			Attachments: paths,
		})
		require.NoError(t, err)

		tree := parseMIMETree(t, msg.String())
		attachments := tree.childrenByDisposition("attachment")
		require.Len(t, attachments, len(names), "one part per attachment, nothing injected")
		assert.Equal(t, names, attachmentNames(attachments), "file names round-trip through the headers")
		for _, part := range attachments {
			assert.Equal(t, []byte("attachment body"), part.content)
		}
	})
}

func TestEmail_buildMessageAttachmentLineLength(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))

	// 57 bytes make exactly 76 base64 characters, i.e. the longest line mime allows
	dir := t.TempDir()
	sizes := []int{1, 57, 58, 1024}
	files := make([]string, 0, len(sizes))
	for _, size := range sizes {
		name := filepath.Join(dir, fmt.Sprintf("attachment-%d.bin", size))
		require.NoError(t, os.WriteFile(name, bytes.Repeat([]byte{'x'}, size), 0o600))
		files = append(files, name)
	}

	msg, err := e.buildMessage("this is a test\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "subj",
		Attachments: files,
	})
	require.NoError(t, err)

	base64Line := regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	for i, line := range strings.Split(msg.String(), "\r\n") {
		if !base64Line.MatchString(line) {
			continue
		}
		assert.LessOrEqual(t, len(line), base64LineLimit, "base64 line %d is too long: %q", i, line)
	}

	tree := parseMIMETree(t, msg.String())
	attachments := tree.childrenByDisposition("attachment")
	require.Len(t, attachments, len(sizes))
	for i, size := range sizes {
		assert.Equal(t, bytes.Repeat([]byte{'x'}, size), attachments[i].content, "attachment of %d bytes", size)
	}
}

func TestLineWrapper(t *testing.T) {
	tests := []struct {
		name     string
		writes   []string
		expected string
	}{
		{"short single write", []string{"12345"}, "12345"},
		{"exactly the limit", []string{"1234567890"}, "1234567890"},
		{"over the limit", []string{"123456789012"}, "1234567890\r\n12"},
		{"split over writes", []string{"12345", "6789012"}, "1234567890\r\n12"},
		{"several lines", []string{"123456789012345678901"}, "1234567890\r\n1234567890\r\n1"},
		{"nothing written", []string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buff := &bytes.Buffer{}
			lw := &lineWrapper{w: buff, limit: 10}
			for _, w := range tt.writes {
				n, err := lw.Write([]byte(w))
				require.NoError(t, err)
				assert.Equal(t, len(w), n, "all the bytes given are reported as written")
			}
			assert.Equal(t, tt.expected, buff.String())
		})
	}
}

func BenchmarkBuildMessageWithAttachment(b *testing.B) {
	file := filepath.Join(b.TempDir(), "attachment.bin")
	require.NoError(b, os.WriteFile(file, bytes.Repeat([]byte{'x'}, 4*1024*1024), 0o600))

	e := NewSender("localhost", ContentType("text/html"))
	params := Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "subj",
		Attachments: []string{file},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, err := e.buildMessage("this is a test\n", params)
		require.NoError(b, err)
		require.NotZero(b, msg.Len())
	}
}

func TestWriteAttachmentsFailed(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{fail: true}
	mp := multipart.NewWriter(wc)
	err := e.writeFiles(mp, []string{"testdata/1.txt"}, "attachment")
	require.Error(t, err)
}

func TestWriteBody(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{buff: &bytes.Buffer{}}
	err := e.writeBody(wc, "this is a test 12345")
	require.NoError(t, err)
	assert.Equal(t, "this is a test 12345", wc.buff.String())
}

func TestWriteBodyFail(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{fail: true}
	err := e.writeBody(wc, "this is a test 12345")
	require.Error(t, err)
}

func TestSender_String(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"), Port(2525), Auth("user", "pass"))
	assert.Equal(t, `smtp://localhost:2525, helo:"localhost", auth:true, tls:false, starttls:false, insecureSkipVerify:false, timeout:30s, content-type:"text/html", charset:"UTF-8"`,
		e.String())

	e = NewSender("localhost", ContentType("text/html"), Port(2525), TLS(true), STARTTLS(true), InsecureSkipVerify(true),
		TimeOut(10*time.Second), HELOHost("client.example.net"))
	assert.Equal(t, `smtp://localhost:2525, helo:"client.example.net", auth:false, tls:true, starttls:true, insecureSkipVerify:true, timeout:10s, content-type:"text/html", charset:"UTF-8"`,
		e.String())

	e = NewSender("localhost", SMTP(&mocks.SMTPClientMock{}))
	assert.Equal(t, `smtp://localhost:25, helo:"client-managed", auth:false, tls:false, starttls:false, insecureSkipVerify:false, timeout:30s, content-type:"text/plain", charset:"UTF-8"`, e.String())
}

// uncomment to debug with real smtp server
// func TestSendIntegration(t *testing.T) {
//	client := NewSender("localhost", ContentType("text/html"), Port(2525))
//	err := client.Send("<html><div>some content, foo bar</div>\n<div><img src=\"cid:image.jpg\"/>\n</div></html>",
//		Params{From: "me@example.com", To: []string{"to@example.com"}, Subject: "Hello world!",
//			Attachments: []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"},
//			InlineImages: []string{"testdata/image.jpg"},
//		})
//	require.NoError(t, err)
// }

type fakeWriterCloser struct {
	buff     *bytes.Buffer
	fail     bool
	closeErr error
	closed   bool
}

func (wc *fakeWriterCloser) Write(p []byte) (n int, err error) {
	if wc.fail {
		return 0, errors.New("write error")
	}
	return wc.buff.Write(p)
}

func (wc *fakeWriterCloser) Close() error {
	wc.closed = true
	return wc.closeErr
}

func startSMTPTestServer(t *testing.T, handler func(net.Conn) error) (host string, port int, done <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	result := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		result <- handler(conn)
	}()

	address := listener.Addr().(*net.TCPAddr)
	return address.IP.String(), address.Port, result
}

func waitSMTPTestServer(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for SMTP test server")
	}
}

func readSMTPCommand(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func writeSMTPResponse(conn net.Conn, response string) error {
	_, err := io.WriteString(conn, response+"\r\n")
	return err
}

func expectSMTPQuit(conn net.Conn, reader *bufio.Reader) error {
	cmd, err := readSMTPCommand(reader)
	if err != nil {
		return err
	}
	if cmd != "QUIT" {
		return fmt.Errorf("unexpected command %q, want QUIT", cmd)
	}
	return writeSMTPResponse(conn, "221 bye")
}

func expectSMTPConnectionClosed(conn net.Conn, reader *bufio.Reader) error {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := reader.ReadByte()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("SMTP connection remained open")
	}
	return fmt.Errorf("waiting for SMTP connection close: %w", err)
}

func smtpTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtp.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS12,
	}
}

func TestExtractEmailAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"bare email", "john@example.com", "john@example.com"},
		{"with display name quoted", `"John Doe" <john@example.com>`, "john@example.com"},
		{"with display name unquoted", "John Doe <john@example.com>", "john@example.com"},
		{"angle brackets only", "<john@example.com>", "john@example.com"},
		{"with leading whitespace", "  john@example.com", "john@example.com"},
		{"with trailing whitespace", "john@example.com  ", "john@example.com"},
		{"display name with whitespace", "  \"John Doe\" <john@example.com>  ", "john@example.com"},
		{"invalid email returns original", "not-an-email", "not-an-email"},
		{"empty string returns original", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractEmailAddress(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mimeNode is a parsed MIME part, used to assert message structure in tests
type mimeNode struct {
	mediaType   string
	disposition string
	fileName    string
	contentID   string
	content     []byte // decoded content of a leaf part
	children    []mimeNode
}

// firstChild returns the first direct child with the given media type
func (n mimeNode) firstChild(mediaType string) (mimeNode, bool) {
	for _, c := range n.children {
		if c.mediaType == mediaType {
			return c, true
		}
	}
	return mimeNode{}, false
}

// childrenByDisposition returns the direct children with the given content-disposition
func (n mimeNode) childrenByDisposition(disposition string) []mimeNode {
	res := make([]mimeNode, 0, len(n.children))
	for _, c := range n.children {
		if c.disposition == disposition {
			res = append(res, c)
		}
	}
	return res
}

// attachmentNames returns the file names of the given parts, in order
func attachmentNames(parts []mimeNode) []string {
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		res = append(res, p.fileName)
	}
	return res
}

// parseMIMETree parses a raw email message and returns its MIME part tree,
// failing the test if the message or any part is not well-formed
func parseMIMETree(t *testing.T, raw string) mimeNode {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	require.NoError(t, err)
	return readMIMENode(t, m.Header.Get("Content-Type"), "", "", "", m.Body)
}

func readMIMENode(t *testing.T, contentType, disposition, contentID, encoding string, body io.Reader) mimeNode {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	node := mimeNode{mediaType: mediaType, disposition: disposition, contentID: contentID}
	if !strings.HasPrefix(mediaType, "multipart/") {
		content, readErr := io.ReadAll(body)
		require.NoError(t, readErr)
		if strings.EqualFold(encoding, "base64") { // the decoder ignores the line breaks mime requires
			decoded, decodeErr := base64.StdEncoding.DecodeString(string(content))
			require.NoError(t, decodeErr, "part content is valid base64")
			content = decoded
		}
		node.content = content
		return node
	}
	mr := multipart.NewReader(body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		disp, fileName := "", ""
		if d := p.Header.Get("Content-Disposition"); d != "" {
			var dispParams map[string]string
			disp, dispParams, _ = mime.ParseMediaType(d)
			fileName = dispParams["filename"]
		}
		child := readMIMENode(t, p.Header.Get("Content-Type"), disp, p.Header.Get("Content-Id"), p.Header.Get("Content-Transfer-Encoding"), p)
		child.fileName = fileName
		node.children = append(node.children, child)
	}
	return node
}
