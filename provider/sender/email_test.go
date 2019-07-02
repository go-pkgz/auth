package sender

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-pkgz/auth/logger"
)

// func TestEmailSend(t *testing.T) {
// 	e := Email{
// 		From:        "test@umputun.com",
// 		L:           logger.Std,
// 		ContentType: "text/html",
// 		Host:        "192.168.1.24",
// 		Port:        25,
// 		Subject:     "test email",
// 	}
//
// 	msg := `
// <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
// <html>
// <body>
// <h2>rest</h2>
// <pre>xyz</pre>
// </body>
// </html>
// `
// 	err := e.Send("sys@umputun.dev", msg)
// 	assert.NoError(t, err)
// }

func TestEmail_buildMessage(t *testing.T) {
	e := Email{
		From:    "from@example.com",
		Subject: "subj",
		L:       logger.Std,
	}

	msg := e.buildMessage("this is a test\n12345", "to@example.com")
	assert.Equal(t, "From: from@example.com\nTo: to@example.com\nSubject: subj\n\nthis is a test\n12345", msg)
}

func TestEmail_buildMessageWithMIME(t *testing.T) {
	e := Email{
		From:        "from@example.com",
		L:           logger.Std,
		ContentType: "text/html",
		Subject:     "subj",
	}

	msg := e.buildMessage("this is a test\n12345", "to@example.com")
	assert.Equal(t, "From: from@example.com\nTo: to@example.com\nSubject: subj\nMIME-version: 1."+
		"0;\nContent-Type: text/html; charset=\"UTF-8\";\n\nthis is a test\n12345", msg)
}
