package avatar

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoOp_Close(t *testing.T) {
	p := NewNoOp()
	err := p.Close()
	require.NoError(t, err)
}

func TestNoOp_Get(t *testing.T) {
	p := NewNoOp()
	reader, size, err := p.Get("blah")
	require.NoError(t, err)
	require.Zero(t, size)
	err = reader.Close()
	require.NoError(t, err)

	proxy := Proxy{
		L:           nil,
		Store:       p,
		RoutePath:   "/avatar",
		URL:         "http://127.0.0.1:8080",
		ResizeLimit: 0,
	}

	ts := httptest.NewServer(http.HandlerFunc(proxy.Handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/avatar")
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Zero(t, resp.ContentLength)
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Empty(t, body)
	err = resp.Body.Close()
	require.NoError(t, err)

}

func TestNoOp_ID(t *testing.T) {
	p := NewNoOp()
	id := p.ID("blah")
	require.Empty(t, id)
}

func TestNoOp_List(t *testing.T) {
	p := NewNoOp()
	ids, err := p.List()
	require.NoError(t, err)
	require.Empty(t, ids)
}

func TestNoOp_Put(t *testing.T) {
	p := NewNoOp()
	avatarID, err := p.Put("blah", nil)
	require.NoError(t, err)
	require.Empty(t, avatarID)
}

func TestNoOp_Remove(t *testing.T) {
	p := NewNoOp()
	err := p.Remove("blah")
	require.NoError(t, err)
}

func TestNoOp_String(t *testing.T) {
	p := NewNoOp()
	s := p.String()
	require.Empty(t, s)
}
