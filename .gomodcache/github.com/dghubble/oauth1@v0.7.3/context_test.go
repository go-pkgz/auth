package oauth1

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextTransport(t *testing.T) {
	client := &http.Client{
		Transport: http.DefaultTransport,
	}
	ctx := context.WithValue(NoContext, HTTPClient, client)
	assert.Equal(t, http.DefaultTransport, contextTransport(ctx))
}

func TestContextTransport_NoContextClient(t *testing.T) {
	assert.Nil(t, contextTransport(NoContext))
}
