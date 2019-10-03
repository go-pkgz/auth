package avatar

import (
	"errors"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
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
	pgfs := prepGFStore(t)

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

func TestStore_NewStore(t *testing.T) {
	tbl := []struct {
		uri string
		res string
		err error
	}{
		{"/tmp/ava_tmp", "localfs, path=/tmp/ava_tmp", nil},
		{"file:///tmp/ava_tmp", "localfs, path=/tmp/ava_tmp", nil},
		{"bolt:///tmp/ava_tmp", "boltdb, path=/tmp/ava_tmp", nil},
		{"mongodb://127.0.0.1:27017/test?ava_db=db1&ava_coll=coll1", "mongo (grid fs), db=db1, bucket=coll1", nil},
		{"mongodb://127.0.0.2:27017/test?ava_db=db1&ava_coll=coll1", "", errors.New("failed to connect to mongo server: context deadline exceeded")},
		{"blah:///tmp/ava_tmp", "", errors.New("can't parse store url blah:///tmp/ava_tmp")},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			res, err := NewStore(tt.uri)
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.res, res.String())
		})
	}
}

func TestStore_parseExtMongoURI(t *testing.T) {
	tbl := []struct {
		name        string
		inp         string
		db, coll, u string
		err         error
	}{
		{"simple", "blah", "test", "avatars_fs", "blah", nil},
		{"both", "mongodb://user:password@127.0.0.1:27017/test?ssl=true&ava_db=db1&ava_coll=coll1", "db1", "coll1",
			"mongodb://user:password@127.0.0.1:27017/test?ssl=true", nil},
		{"default_both", "mongodb://user:password@127.0.0.1:27017/test?ssl=true&xyz=123", "test", "avatars_fs",
			"mongodb://user:password@127.0.0.1:27017/test?ssl=true&xyz=123", nil},
		{"default_db", "mongodb://user:password@127.0.0.1:27017/test?ssl=true&xyz=123&ava_coll=coll1", "test", "coll1",
			"mongodb://user:password@127.0.0.1:27017/test?ssl=true&xyz=123", nil},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			db, coll, u, err := parseExtMongoURI(tt.inp)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.db, db)
			assert.Equal(t, tt.coll, coll)
			assert.Equal(t, tt.u, u)
		})
	}
}
