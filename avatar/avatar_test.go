package avatar

import (
	"bytes"
	"fmt"
	"image"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

func TestAvatar_Put(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pic.png" {
			w.Header().Set("Content-Type", "image/*")
			fmt.Fprint(w, "some picture bin data")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer func() {
		_ = os.RemoveAll("/tmp/avatars.test/")
		ts.Close()
	}()

	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: NewLocalFS("/tmp/avatars.test"), L: logger.NoOp}
	assert.NoError(t, os.MkdirAll("/tmp/avatars.test", 0o700))
	defer os.RemoveAll("/tmp/avatars.test")

	client := &http.Client{Timeout: time.Second}
	u := token.User{ID: "user1", Name: "user1 name", Picture: ts.URL + "/pic.png"}
	res, err := p.Put(u, client)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/b3daa77b4c04a9551b8781d03191fe098f325e67.image", res)
	fi, err := os.Stat("/tmp/avatars.test/30/b3daa77b4c04a9551b8781d03191fe098f325e67.image")
	assert.NoError(t, err)
	assert.Equal(t, int64(21), fi.Size())

	u.ID = "user2"
	res, err = p.Put(u, client)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image", res)
	fi, err = os.Stat("/tmp/avatars.test/84/a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image")
	assert.NoError(t, err)
	assert.Equal(t, int64(21), fi.Size())
}

func TestAvatar_PutIdenticon(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Print("request: ", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer func() {
		_ = os.RemoveAll("/tmp/avatars.test/")
		ts.Close()
	}()
	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: NewLocalFS("/tmp/avatars.test"), L: logger.Std}
	client := &http.Client{Timeout: time.Second}

	u := token.User{ID: "user1", Name: "user1 name"}
	res, err := p.Put(u, client)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/b3daa77b4c04a9551b8781d03191fe098f325e67.image", res)
	fi, err := os.Stat("/tmp/avatars.test/30/b3daa77b4c04a9551b8781d03191fe098f325e67.image")
	assert.NoError(t, err)
	assert.Equal(t, int64(999), fi.Size())

}

func TestAvatar_PutFailed(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Print("request: ", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer func() {
		_ = os.RemoveAll("/tmp/avatars.test/")
		ts.Close()
	}()

	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: NewLocalFS("/tmp/avatars.test"), L: logger.Std}
	client := &http.Client{Timeout: time.Second}

	u := token.User{ID: "user2", Name: "user2 name", Picture: "http://127.0.0.1:22345/avater/pic"}
	res, err := p.Put(u, client)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image", res)
	fi, err := os.Stat("/tmp/avatars.test/84/a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image")
	require.NoError(t, err)
	assert.Equal(t, int64(992), fi.Size())
}

func TestAvatar_Routes(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pic.png" {
			w.Header().Set("Content-Type", "image/*")
			w.Header().Set("Custom-Header", "xyz")
			_, err := fmt.Fprint(w, "some picture bin data")
			require.NoError(t, err)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer ts.Close()

	p := Proxy{RoutePath: "/avatar", Store: NewLocalFS("/tmp/avatars.test"), L: logger.Std}
	assert.NoError(t, os.MkdirAll("/tmp/avatars.test", 0o700))
	defer os.RemoveAll("/tmp/avatars.test")
	client := &http.Client{Timeout: time.Second}

	u := token.User{ID: "user1", Name: "user1 name", Picture: ts.URL + "/pic.png"}
	_, err := p.Put(u, client)
	assert.NoError(t, err)

	{
		// status 400
		req, err := http.NewRequest("GET", "/123aa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	}

	{
		// status 403
		req, err := http.NewRequest("GET", "../not-allowed.txt", http.NoBody)
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	}

	{ // status 200
		req, err := http.NewRequest("GET", "/b3daa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, []string{"image/*"}, rr.Header()["Content-Type"])
		assert.Equal(t, []string{"21"}, rr.Header()["Content-Length"])
		assert.Equal(t, []string(nil), rr.Header()["Custom-Header"], "strip all custom headers")
		assert.NotNil(t, rr.Header()["Etag"])

		bb := bytes.Buffer{}
		sz, err := io.Copy(&bb, rr.Body)
		assert.NoError(t, err)
		assert.Equal(t, int64(21), sz)
		assert.Equal(t, "some picture bin data", bb.String())
	}

	{
		// status 304
		req, err := http.NewRequest("GET", "/b3daa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
		require.NoError(t, err)
		id := p.Store.ID("b3daa77b4c04a9551b8781d03191fe098f325e67.image")
		req.Header.Add("If-None-Match", p.Store.ID(id)) // hash of `some_random_name.image` since the file doesn't exist

		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotModified, rr.Code)
		assert.Equal(t, []string{`"` + id + `"`}, rr.Header()["Etag"])
	}

}

func TestAvatar_resize(t *testing.T) {
	checkC := func(t *testing.T, r io.Reader, cExp []byte) {
		content, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, cExp, content)
	}

	p := Proxy{L: logger.Std}
	// Reader is nil.
	resizedR := p.resize(nil, 100)
	assert.Nil(t, resizedR)

	// Negative limit error.
	resizedR = p.resize(strings.NewReader("some picture bin data"), -1)
	require.NotNil(t, resizedR)
	checkC(t, resizedR, []byte("some picture bin data"))

	// Decode error.
	resizedR = p.resize(strings.NewReader("invalid image content"), 100)
	assert.NotNil(t, resizedR)
	checkC(t, resizedR, []byte("invalid image content"))

	cases := []struct {
		file   string
		wr, hr int
	}{
		{"testdata/circles.png", 400, 300}, // full size: 800x600 px
		{"testdata/circles.jpg", 300, 400}, // full size: 600x800 px
	}

	for _, c := range cases {
		img, err := os.ReadFile(c.file)
		require.Nil(t, err, "can't open test file %s", c.file)

		// No need for resize, avatar dimensions are smaller than resize limit.
		resizedR = p.resize(bytes.NewReader(img), 800)
		assert.NotNil(t, resizedR, "file %s", c.file)
		checkC(t, resizedR, img)

		// Resizing to half of width. Check resizedR avatar format PNG.
		resizedR = p.resize(bytes.NewReader(img), 400)
		assert.NotNil(t, resizedR, "file %s", c.file)

		imgRz, format, err := image.Decode(resizedR)
		assert.NoError(t, err, "file %s", c.file)
		assert.Equal(t, "png", format, "file %s", c.file)
		bounds := imgRz.Bounds()
		assert.Equal(t, c.wr, bounds.Dx(), "file %s", c.file)
		assert.Equal(t, c.hr, bounds.Dy(), "file %s", c.file)
	}
}

func TestAvatar_GetGravatarURL(t *testing.T) {
	tbl := []struct {
		email string
		err   error
		url   string
	}{
		{"eefretsoul@gmail.com", nil, "https://www.gravatar.com/avatar/c82739de14cf64affaf30856ca95b851"},
		{"umputun-xyz@example.com", fmt.Errorf("404 Not Found"), ""},
	}

	for i, tt := range tbl {
		tt := tt
		t.Run("test-"+strconv.Itoa(i), func(t *testing.T) {
			url, err := GetGravatarURL(tt.email)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.url, url)
		})
	}
}

func TestAvatar_Retry(t *testing.T) {
	i := 0
	err := retry(5, time.Millisecond, func() error {
		if i == 3 {
			return nil
		}
		i++
		return fmt.Errorf("err")
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, i)

	st := time.Now()
	err = retry(5, time.Millisecond, func() error {
		return fmt.Errorf("err")
	})
	assert.Error(t, err)
	assert.True(t, time.Since(st) >= time.Microsecond*5)
}
