package rest

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/rest/logger"
)

func TestFileServerDefault(t *testing.T) {
	fh1, err := NewFileServer("/static", "./testdata/root")
	require.NoError(t, err)

	fh2, err := FileServer("/static", "./testdata/root", nil)
	require.NoError(t, err)

	ts1 := httptest.NewServer(logger.Logger(fh1))
	defer ts1.Close()
	ts2 := httptest.NewServer(logger.Logger(fh2))
	defer ts2.Close()

	client := http.Client{Timeout: 599 * time.Second}

	tbl := []struct {
		req    string
		body   string
		status int
	}{
		{"/static", "testdata/index.html", 200},
		{"/static/index.html", "testdata/index.html", 200},
		{"/static/xyz.js", "testdata/xyz.js", 200},
		{"/static/1/", "", 404},
		{"/static/1/nothing", "", 404},
		{"/static/1/f1.html", "testdata/1/f1.html", 200},
		{"/static/2/", "testdata/2/index.html", 200},
		{"/static/2", "testdata/2/index.html", 200},
		{"/static/2/index.html", "testdata/2/index.html", 200},
		{"/static/2/index", "", 404},
		{"/static/2/f123.txt", "testdata/2/f123.txt", 200},
		{"/static/1/../", "testdata/index.html", 200},
		{"/static/../", "testdata/index.html", 200},
		{"/static/../../", "testdata/index.html", 200},
		{"/static/../../../", "testdata/index.html", 200},
		{"/static/%2e%2e%2f%2e%2e%2f%2e%2e%2f/", "testdata/index.html", 200},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			for _, ts := range []*httptest.Server{ts1, ts2} {
				req, err := http.NewRequest("GET", ts.URL+tt.req, http.NoBody)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err)
				t.Logf("headers: %v", resp.Header)
				assert.Equal(t, tt.status, resp.StatusCode)
				if resp.StatusCode == http.StatusNotFound {
					msg, e := io.ReadAll(resp.Body)
					require.NoError(t, e)
					assert.Equal(t, "404 page not found\n", string(msg))
					return
				}
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, tt.body, string(body))
			}
		})
	}
}

func TestFileServerWithListing(t *testing.T) {
	fh, err := NewFileServer("/static", "./testdata/root", FsOptListing)
	require.NoError(t, err)
	ts := httptest.NewServer(logger.Logger(fh))
	defer ts.Close()
	client := http.Client{Timeout: 599 * time.Second}

	{
		req, err := http.NewRequest("GET", ts.URL+"/static/1", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		msg, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		exp := `<pre>
<a href="f1.html">f1.html</a>
<a href="f2.html">f2.html</a>
</pre>
`
		assert.Contains(t, string(msg), exp)
	}

	{
		req, err := http.NewRequest("GET", ts.URL+"/static/xyz.js", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		msg, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "testdata/xyz.js", string(msg))
		assert.True(t, strings.Contains(resp.Header.Get("Content-Type"), "javascript"), resp.Header.Get("Content-Type"))
	}

	{
		req, err := http.NewRequest("GET", ts.URL+"/static/no-such-thing.html", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	}
}

func TestFileServer_Custom404(t *testing.T) {
	nf := FsOptCustom404(bytes.NewBufferString("custom 404"))
	fh, err := NewFileServer("/static", "./testdata/root", nf)
	require.NoError(t, err)
	ts := httptest.NewServer(logger.Logger(fh))
	defer ts.Close()
	client := http.Client{Timeout: 599 * time.Second}

	{
		req, err := http.NewRequest("GET", ts.URL+"/static/xyz.js", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		msg, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "testdata/xyz.js", string(msg))
		assert.True(t, strings.Contains(resp.Header.Get("Content-Type"), "javascript"), resp.Header.Get("Content-Type"))
	}

	{
		req, err := http.NewRequest("GET", ts.URL+"/static/nofile.js", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		msg, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "custom 404", string(msg))
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	}

	{
		req, err := http.NewRequest("GET", ts.URL+"/xyz.html", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		msg, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "custom 404", string(msg))
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	}

	{
		req, err := http.NewRequest("GET", ts.URL+"/static/xyz.js", http.NoBody)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		msg, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "testdata/xyz.js", string(msg))
	}
}

func TestFileServerSPA(t *testing.T) {
	fh1, err := NewFileServer("/static", "./testdata/root", FsOptSPA)
	require.NoError(t, err)
	fh2, err := FileServerSPA("/static", "./testdata/root", nil)
	require.NoError(t, err)

	ts1 := httptest.NewServer(logger.Logger(fh1))
	defer ts1.Close()
	ts2 := httptest.NewServer(logger.Logger(fh2))
	defer ts2.Close()
	client := http.Client{Timeout: 599 * time.Second}

	tbl := []struct {
		req    string
		body   string
		status int
	}{
		{"/static/blah", "testdata/index.html", 200},
		{"/static/blah/foo/123.html", "testdata/index.html", 200},
		{"/static", "testdata/index.html", 200},
		{"/static/index.html", "testdata/index.html", 200},
		{"/static/xyz.js", "testdata/xyz.js", 200},
		{"/static/1/", "", 404},
		{"/static/1/nothing", "testdata/index.html", 200},
		{"/static/1/f1.html", "testdata/1/f1.html", 200},
		{"/static/2/", "testdata/2/index.html", 200},
		{"/static/2", "testdata/2/index.html", 200},
		{"/static/2/index.html", "testdata/2/index.html", 200},
		{"/static/2/index", "testdata/index.html", 200},
		{"/static/2/f123.txt", "testdata/2/f123.txt", 200},
		{"/static/1/../", "testdata/index.html", 200},
		{"/static/../", "testdata/index.html", 200},
		{"/static/../../", "testdata/index.html", 200},
		{"/static/../../../", "testdata/index.html", 200},
		{"/static/%2e%2e%2f%2e%2e%2f%2e%2e%2f/", "testdata/index.html", 200},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			for _, ts := range []*httptest.Server{ts1, ts2} {
				req, err := http.NewRequest("GET", ts.URL+tt.req, http.NoBody)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err)
				t.Logf("headers: %v", resp.Header)
				assert.Equal(t, tt.status, resp.StatusCode)
				if resp.StatusCode == http.StatusNotFound {
					msg, e := io.ReadAll(resp.Body)
					require.NoError(t, e)
					assert.Equal(t, "404 page not found\n", string(msg))
					return
				}
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, tt.body, string(body))
			}
		})
	}
}

// trackingFS counts opened and closed handles to catch descriptors customFS forgets to release
type trackingFS struct {
	fs       http.FileSystem
	statFail bool

	mu     sync.Mutex
	opened int
	closed int
}

func (t *trackingFS) Open(name string) (http.File, error) {
	f, err := t.fs.Open(name)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.opened++
	t.mu.Unlock()
	return &trackingFile{File: f, fs: t, statFail: t.statFail}, nil
}

func (t *trackingFS) counts() (opened, closed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.opened, t.closed
}

type trackingFile struct {
	http.File
	fs       *trackingFS
	statFail bool
	once     sync.Once
}

func (f *trackingFile) Stat() (os.FileInfo, error) {
	if f.statFail {
		return nil, errors.New("stat failed")
	}
	return f.File.Stat()
}

func (f *trackingFile) Close() error {
	f.once.Do(func() {
		f.fs.mu.Lock()
		f.fs.closed++
		f.fs.mu.Unlock()
	})
	return f.File.Close()
}

func TestCustomFSHandles(t *testing.T) {
	tbl := []struct {
		name     string
		path     string
		listing  bool
		spa      bool
		statFail bool
		wantErr  bool
	}{
		{name: "dir with index", path: "/", wantErr: false},
		{name: "dir with index, nested", path: "/2", wantErr: false},
		{name: "dir without index, listing disabled", path: "/1", wantErr: true},
		{name: "dir without index, listing enabled", path: "/1", listing: true, wantErr: false},
		{name: "regular file", path: "/xyz.js", wantErr: false},
		{name: "missing file", path: "/nope.js", wantErr: true},
		{name: "missing file, spa", path: "/nope.js", spa: true, wantErr: false},
		{name: "stat failure", path: "/", statFail: true, wantErr: true},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			tfs := &trackingFS{fs: http.Dir("./testdata/root"), statFail: tt.statFail}
			cfs := customFS{fs: tfs, spa: tt.spa, listing: tt.listing}

			f, err := cfs.Open(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, f)
				opened, closed := tfs.counts()
				assert.Equal(t, opened, closed, "every opened handle must be closed on the error path")
				return
			}

			require.NoError(t, err)
			require.NotNil(t, f)
			require.NoError(t, f.Close())

			opened, closed := tfs.counts()
			assert.Equal(t, opened, closed, "probe handles must be closed once the caller closes the result")
		})
	}
}

func TestFileServerNoDescriptorLeak(t *testing.T) {
	tfs := &trackingFS{fs: http.Dir("./testdata/root")}
	cfs := customFS{fs: tfs}

	// repeated directory requests are what accumulated descriptors before
	for range 50 {
		f, err := cfs.Open("/")
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	opened, closed := tfs.counts()
	assert.Equal(t, opened, closed)
	assert.Equal(t, 100, opened, "each directory request opens the dir plus one index probe")
}
