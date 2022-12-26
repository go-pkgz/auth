package avatar

import (
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

var testDB = "/tmp/test-remark-avatars.db"

func TestBoltDB_PutAndGet(t *testing.T) {
	var b Store
	b, teardown := prepBoltStore(t)
	defer teardown()

	avatar, err := b.Put("user1", strings.NewReader("some picture bin data"))
	require.Nil(t, err)
	assert.Equal(t, "b3daa77b4c04a9551b8781d03191fe098f325e67.image", avatar)

	rd, size, err := b.Get(avatar)
	require.Nil(t, err)
	assert.Equal(t, 21, size)
	data, err := io.ReadAll(rd)
	require.Nil(t, err)
	assert.Equal(t, "some picture bin data", string(data))

	_, _, err = b.Get("bad avatar")
	assert.Error(t, err)

	// check IDs
	assert.Equal(t, "fddae9ce556712a6ece0e8951a6e7a05c51ed6bf", b.ID(avatar))
	assert.Equal(t, "70c881d4a26984ddce795f6f71817c9cf4480e79", b.ID("aaaa"), "no data, encoded avatar id")

	l, err := b.List()
	require.Nil(t, err)
	assert.Equal(t, 1, len(l))
	assert.Equal(t, "b3daa77b4c04a9551b8781d03191fe098f325e67.image", l[0])
}

func TestBoltDB_Remove(t *testing.T) {
	b, teardown := prepBoltStore(t)
	defer teardown()

	assert.Error(t, b.Remove("no-such-thing.image"))

	avatar, err := b.Put("user1", strings.NewReader("some picture bin data"))
	require.Nil(t, err)
	assert.Equal(t, "b3daa77b4c04a9551b8781d03191fe098f325e67.image", avatar)
	assert.NoError(t, b.Remove("b3daa77b4c04a9551b8781d03191fe098f325e67.image"), "remove real one")
	assert.Error(t, b.Remove("b3daa77b4c04a9551b8781d03191fe098f325e67.image"), "already removed")
}

func TestBoltDB_List(t *testing.T) {
	b, teardown := prepBoltStore(t)
	defer teardown()

	// write some avatars
	_, err := b.Put("user1", strings.NewReader("some picture bin data 1"))
	require.Nil(t, err)
	_, err = b.Put("user2", strings.NewReader("some picture bin data 2"))
	require.Nil(t, err)
	_, err = b.Put("user3", strings.NewReader("some picture bin data 3"))
	require.Nil(t, err)

	l, err := b.List()
	assert.NoError(t, err)
	assert.Equal(t, 3, len(l), "3 avatars listed")
	sort.Strings(l)
	assert.Equal(t, []string{"0b7f849446d3383546d15a480966084442cd2193.image", "a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image", "b3daa77b4c04a9551b8781d03191fe098f325e67.image"}, l)

	r, size, err := b.Get("0b7f849446d3383546d15a480966084442cd2193.image")
	assert.NoError(t, err)
	assert.Equal(t, 23, size)
	data, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, "some picture bin data 3", string(data))
}

func TestBoltDB_DoubleClose(t *testing.T) {
	_ = os.Remove(testDB)
	boltStore, err := NewBoltDB(testDB, bolt.Options{})
	require.Nil(t, err)
	assert.NoError(t, boltStore.Close())
	assert.NoError(t, boltStore.Close(), "second call should not result in panic or errors")
	_ = os.Remove(testDB)
}

// makes new boltdb, put two records
func prepBoltStore(t *testing.T) (blt *BoltDB, teardown func()) {
	_ = os.Remove(testDB)
	boltStore, err := NewBoltDB(testDB, bolt.Options{})
	require.Nil(t, err)
	return boltStore, func() {
		assert.NoError(t, boltStore.Close())
		_ = os.Remove(testDB)
	}
}
