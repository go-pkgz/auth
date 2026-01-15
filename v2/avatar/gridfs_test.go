package avatar

import (
	"context"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestGridFS_PutAndGet(t *testing.T) {
	if _, ok := os.LookupEnv("ENABLE_MONGO_TESTS"); !ok {
		t.Skip("ENABLE_MONGO_TESTS env variable is not set")
	}
	p := prepGFStore(t)
	defer p.Close()
	avatar, err := p.Put("user1", strings.NewReader("some picture bin data"))
	require.Nil(t, err)
	assert.Equal(t, "b3daa77b4c04a9551b8781d03191fe098f325e67.image", avatar)

	rd, size, err := p.Get(avatar)
	require.Nil(t, err)
	assert.Equal(t, 21, size)
	data, err := io.ReadAll(rd)
	require.Nil(t, err)
	assert.Equal(t, "some picture bin data", string(data))

	_, _, err = p.Get("bad avatar")
	assert.Error(t, err)
	assert.Equal(t, "fddae9ce556712a6ece0e8951a6e7a05c51ed6bf", p.ID(avatar))
	assert.Equal(t, "70c881d4a26984ddce795f6f71817c9cf4480e79", p.ID("aaaa"), "no data, encode avatar id")

	l, err := p.List()
	require.Nil(t, err)
	assert.Equal(t, 1, len(l))
	assert.Equal(t, "b3daa77b4c04a9551b8781d03191fe098f325e67.image", l[0])
}

func TestGridFS_Remove(t *testing.T) {
	if _, ok := os.LookupEnv("ENABLE_MONGO_TESTS"); !ok {
		t.Skip("ENABLE_MONGO_TESTS env variable is not set")
	}
	p := prepGFStore(t)
	defer p.Close()
	assert.Error(t, p.Remove("no-such-thing.image"))
	avatar, err := p.Put("user1", strings.NewReader("some picture bin data"))
	require.Nil(t, err)
	assert.Equal(t, "b3daa77b4c04a9551b8781d03191fe098f325e67.image", avatar)
	assert.NoError(t, p.Remove("b3daa77b4c04a9551b8781d03191fe098f325e67.image"), "remove real one")
	assert.Error(t, p.Remove("b3daa77b4c04a9551b8781d03191fe098f325e67.image"), "already removed")
}

func TestGridFS_List(t *testing.T) {
	if _, ok := os.LookupEnv("ENABLE_MONGO_TESTS"); !ok {
		t.Skip("ENABLE_MONGO_TESTS env variable is not set")
	}
	p := prepGFStore(t)
	defer p.Close()

	// write some avatars
	_, err := p.Put("user1", strings.NewReader("some picture bin data 1"))
	require.Nil(t, err)
	_, err = p.Put("user2", strings.NewReader("some picture bin data 2"))
	require.Nil(t, err)
	_, err = p.Put("user3", strings.NewReader("some picture bin data 3"))
	require.Nil(t, err)

	l, err := p.List()
	assert.NoError(t, err)
	assert.Equal(t, 3, len(l), "3 avatars listed")
	sort.Strings(l)
	assert.Equal(t, []string{"0b7f849446d3383546d15a480966084442cd2193.image", "a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image", "b3daa77b4c04a9551b8781d03191fe098f325e67.image"}, l)

	r, size, err := p.Get("0b7f849446d3383546d15a480966084442cd2193.image")
	assert.NoError(t, err)
	assert.Equal(t, 23, size)
	data, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, "some picture bin data 3", string(data))
}

func TestGridFS_DoubleClose(t *testing.T) {
	if _, ok := os.LookupEnv("ENABLE_MONGO_TESTS"); !ok {
		t.Skip("ENABLE_MONGO_TESTS env variable is not set")
	}
	p := prepGFStore(t)
	assert.NoError(t, p.Close())
	assert.NoError(t, p.Close(), "second call should not result in panic or errors")
}

func prepGFStore(t *testing.T) *GridFS {
	const timeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017").SetConnectTimeout(timeout))
	require.NoError(t, err)

	_ = client.Database("test").Collection("ava_fs.chunks").Drop(ctx)
	_ = client.Database("test").Collection("ava_fs.files").Drop(ctx)

	return NewGridFS(client, "test", "ava_fs", time.Second)
}
