package avatar

import (
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAvatarStore_Migrate(t *testing.T) {
	// prep localfs
	plocal := NewLocalFS("/tmp/avatars.test")
	err := os.MkdirAll("/tmp/avatars.test", 0700)
	require.NoError(t, err)
	defer os.RemoveAll("/tmp/avatars.test")

	// prep gridfs
	pgfs, skip := prepGFStore(t)
	if skip {
		return
	}

	// write to localfs
	_, err = plocal.Put("user1", strings.NewReader("some picture bin data 1"))
	require.Nil(t, err)
	_, err = plocal.Put("user2", strings.NewReader("some picture bin data 2"))
	require.Nil(t, err)
	_, err = plocal.Put("user3", strings.NewReader("some picture bin data 3"))
	require.Nil(t, err)

	// migrate and check reported count
	count, err := Migrate(pgfs, plocal)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "all 3 recs migrated")

	// list avatars
	l, err := pgfs.List()
	assert.NoError(t, err)
	assert.Equal(t, 3, len(l), "3 avatars listed in destination store")
	sort.Strings(l)
	assert.Equal(t, []string{"0b7f849446d3383546d15a480966084442cd2193.image", "a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image", "b3daa77b4c04a9551b8781d03191fe098f325e67.image"}, l)

	// try to read one of migrated avatars
	r, size, err := pgfs.Get("0b7f849446d3383546d15a480966084442cd2193.image")
	assert.Nil(t, err)
	assert.Equal(t, 23, size)
	data, err := ioutil.ReadAll(r)
	assert.Nil(t, err)
	assert.Equal(t, "some picture bin data 3", string(data))
}
