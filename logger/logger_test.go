package logger

import (
	"bytes"
	"fmt"
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
}
