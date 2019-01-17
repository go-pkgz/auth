package logger

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogger(t *testing.T) {
	buff := bytes.NewBufferString("")
	lg := Func(func(format string, args ...interface{}) {
		fmt.Fprintf(buff, format, args...)
	})

	lg.Logf("blah %s %d something", "str", 123)
	assert.Equal(t, "blah str 123 something", buff.String())

	Std.Logf("blah %s %d something", "str", 123)
	Std.Logf("[DEBUG] auth failed, %s", errors.New("blah blah"))
}

func TestStd(t *testing.T) {
	buff := bytes.NewBufferString("")
	log.SetOutput(buff)
	defer log.SetOutput(os.Stdout)

	Std.Logf("blah %s %d something", "str", 123)
	assert.True(t, strings.HasSuffix(buff.String(), "blah str 123 something\n"), buff.String())
}

func TestNoOp(t *testing.T) {
	buff := bytes.NewBufferString("")
	log.SetOutput(buff)
	defer log.SetOutput(os.Stdout)

	NoOp.Logf("blah %s %d something", "str", 123)
	assert.Equal(t, "", buff.String())
}
