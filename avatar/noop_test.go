package avatar

import (
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
	require.Nil(t, reader)
	require.Zero(t, size)
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
