package email

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/email/mocks"
)

func TestEmail_SendContext(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		body := strings.Builder{}
		for {
			cmd, err := readSMTPCommand(reader)
			if err != nil {
				return err
			}
			switch cmd {
			case "DATA":
				if e := writeSMTPResponse(conn, "354 send the message"); e != nil {
					return e
				}
				for {
					line, e := readSMTPCommand(reader)
					if e != nil {
						return e
					}
					if line == "." {
						break
					}
					body.WriteString(line + "\n")
				}
				if e := writeSMTPResponse(conn, "250 queued"); e != nil {
					return e
				}
			case "QUIT":
				if !strings.Contains(body.String(), "test body") {
					return fmt.Errorf("unexpected message body %q", body.String())
				}
				return writeSMTPResponse(conn, "221 bye")
			default:
				if e := writeSMTPResponse(conn, "250 ok"); e != nil {
					return e
				}
			}
		}
	})

	sender := NewSender(host, Port(port), TimeOut(time.Second*5))
	params := Params{From: "from@example.com", To: []string{"to@example.com"}, Subject: "subj"}
	require.NoError(t, sender.SendContext(context.Background(), "test body", params))
	waitSMTPTestServer(t, done)
}

func TestEmail_SendContextStalledServer(t *testing.T) {
	// server greets and stops responding, which is how a hanging server looks to the client
	stalledServer := func(t *testing.T) (host string, port int, done <-chan error) {
		return startSMTPTestServer(t, func(conn net.Conn) error {
			if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
				return err
			}
			_, err := io.Copy(io.Discard, conn) // consume the commands and never answer
			return err
		})
	}
	params := Params{From: "from@example.com", To: []string{"to@example.com"}, Subject: "subj"}

	t.Run("context deadline", func(t *testing.T) {
		host, port, done := stalledServer(t)
		// connection timeout is long on purpose, the context and not the timeout should end the transaction
		sender := NewSender(host, Port(port), TimeOut(time.Minute))

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		st := time.Now()
		require.Error(t, sender.SendContext(ctx, "test body", params))
		assert.Less(t, time.Since(st), time.Second*3, "transaction ended on the context deadline")
		waitSMTPTestServer(t, done)
	})

	t.Run("canceled in flight", func(t *testing.T) {
		host, port, done := stalledServer(t)
		sender := NewSender(host, Port(port), TimeOut(time.Minute))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(time.Millisecond*100, cancel)

		st := time.Now()
		require.Error(t, sender.SendContext(ctx, "test body", params))
		assert.Less(t, time.Since(st), time.Second*3, "transaction ended on cancellation")
		waitSMTPTestServer(t, done)
	})

	t.Run("canceled before the call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// no server, canceled context should be detected before any connection attempt
		sender := NewSender("127.0.0.1", Port(1), TimeOut(time.Minute))
		require.ErrorIs(t, sender.SendContext(ctx, "test body", params), context.Canceled)
	})

	t.Run("canceled before the call with a client set with the SMTP option", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		smtpClient := &mocks.SMTPClientMock{
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return nil, nil },
		}

		sender := NewSender("localhost", SMTP(smtpClient))
		require.ErrorIs(t, sender.SendContext(ctx, "test body", params), context.Canceled)
		assert.Empty(t, smtpClient.MailCalls(), "nothing started")
		assert.Len(t, smtpClient.CloseCalls(), 1, "client set with the SMTP option is closed on every failure")
	})
}
