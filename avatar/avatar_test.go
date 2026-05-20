package avatar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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
	pngBytes, err := os.ReadFile("testdata/circles.png")
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pic.png" {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(pngBytes)
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
	assert.Equal(t, int64(len(pngBytes)), fi.Size())

	u.ID = "user2"
	res, err = p.Put(u, client)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image", res)
	fi, err = os.Stat("/tmp/avatars.test/84/a1881c06eec96db9901c7bbfe41c42a3f08e9cb4.image")
	assert.NoError(t, err)
	assert.Equal(t, int64(len(pngBytes)), fi.Size())
}

// TestAvatar_PutRejectsNonImage proves that an attacker controlling u.Picture cannot
// poison the avatar store with HTML/SVG/text — Put falls back to an identicon and the
// stored bytes are guaranteed to be a real PNG, not the attacker payload.
func TestAvatar_PutRejectsNonImage(t *testing.T) {
	htmlPayload := []byte("<html><script>alert(document.domain)</script></html>")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png") // lying upstream
		_, _ = w.Write(htmlPayload)
	}))
	defer ts.Close()

	dir := t.TempDir()
	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: NewLocalFS(dir), L: logger.Std}

	u := token.User{ID: "user1", Name: "user1 name", Picture: ts.URL + "/evil.png"}
	res, err := p.Put(u, &http.Client{Timeout: time.Second})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/b3daa77b4c04a9551b8781d03191fe098f325e67.image", res)

	stored, err := os.ReadFile(dir + "/30/b3daa77b4c04a9551b8781d03191fe098f325e67.image")
	require.NoError(t, err)
	assert.NotEqual(t, htmlPayload, stored, "attacker payload must not be stored")
	assert.NotContains(t, string(stored), "<script>", "attacker payload must not be reachable from the store")
	assert.True(t, bytes.HasPrefix(stored, []byte{0x89, 'P', 'N', 'G'}), "fallback content must be a real PNG (identicon)")
}

func TestAvatar_PutContent(t *testing.T) {
	pngBytes, err := os.ReadFile("testdata/circles.png")
	require.NoError(t, err)

	defer func() { _ = os.RemoveAll("/tmp/avatars.put-content.test/") }()
	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: NewLocalFS("/tmp/avatars.put-content.test"), L: logger.Std}
	got, err := p.PutContent("user1", bytes.NewReader(pngBytes))
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/avatar/b3daa77b4c04a9551b8781d03191fe098f325e67.image", got)
	fi, err := os.Stat("/tmp/avatars.put-content.test/30/b3daa77b4c04a9551b8781d03191fe098f325e67.image")
	require.NoError(t, err)
	assert.Greater(t, fi.Size(), int64(0))

	// non-image bytes are rejected — never stored
	_, err = p.PutContent("attacker", strings.NewReader("<html><script>alert(1)</script></html>"))
	require.Error(t, err, "non-image content must be rejected at PutContent")
	assert.Contains(t, err.Error(), "not a valid image")
}

// TestAvatar_HandlerRejectsPoisonedStore proves that even if the store contains
// attacker-controlled non-image bytes (e.g. poisoned before the fix), Handler refuses
// to serve them and returns 415 with strict defense headers instead.
func TestAvatar_HandlerRejectsPoisonedStore(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalFS(dir)

	// directly seed the store with an HTML payload at user1's avatar id
	htmlPayload := []byte("<html><body><script>alert(document.domain)</script></body></html>")
	_, err := store.Put("user1", bytes.NewReader(htmlPayload))
	require.NoError(t, err)

	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: store, L: logger.Std}

	req := httptest.NewRequest("GET", "/avatar/b3daa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
	rr := httptest.NewRecorder()
	p.Handler(rr, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code, "poisoned store bytes must be rejected at serve time")
	assert.False(t, strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html"),
		"reject response must not be text/html (got %q)", rr.Header().Get("Content-Type"))
	assert.NotContains(t, rr.Body.String(), "<script>", "attacker payload must never appear in response body")
	// defense headers on the rejection path too
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, rr.Header().Get("Content-Disposition"), "inline")
	csp := rr.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'none'")
	assert.Contains(t, csp, "sandbox")
}

func TestAvatar_RedactAvatarURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{in: "https://api.telegram.org/file/botSECRET/photo.jpg", want: "api.telegram.org"},
		{in: "https://x:y@example.com/path?q=1", want: "example.com"}, // #nosec G101 -- deliberate test fixture for userinfo redaction
		{in: "", want: "<unparseable>"},
		{in: "/local/path", want: "<unparseable>"},
		{in: "://malformed", want: "<unparseable>"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, redactAvatarURL(c.in))
		})
	}
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

func TestAvatar_PutCapsBodySize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/*")
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 64<<10)
		for i := 0; i < (maxAvatarFetchSize/len(buf))+32; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	p := Proxy{RoutePath: "/avatar", URL: "http://localhost:8080", Store: NewLocalFS(dir), L: logger.NoOp}
	client := &http.Client{Timeout: 5 * time.Second}

	u := token.User{ID: "user1", Name: "huge avatar", Picture: ts.URL + "/pic.png"}
	res, err := p.Put(u, client)
	require.NoError(t, err, "Put falls back to identicon on capped fetch failure")
	assert.Contains(t, res, "/avatar/", "still returns a proxy URL via identicon fallback")
}

func TestAvatar_Routes(t *testing.T) {
	pngBytes, err := os.ReadFile("testdata/circles.png")
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pic.png" {
			w.Header().Set("Content-Type", "image/jpg") // intentionally wrong upstream CT — proxy must ignore it
			w.Header().Set("Custom-Header", "xyz")
			_, wrErr := w.Write(pngBytes)
			require.NoError(t, wrErr)
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
	_, err = p.Put(u, client)
	assert.NoError(t, err)

	{
		// status 400
		req, e := http.NewRequest("GET", "/123aa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
		require.NoError(t, e)
		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	}

	{
		// status 403
		req, e := http.NewRequest("GET", "../not-allowed.txt", http.NoBody)
		require.NoError(t, e)
		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	}

	{ // status 200 — real PNG bytes round-trip and are served as image/png (upstream lied with image/jpg)
		req, e := http.NewRequest("GET", "/b3daa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
		require.NoError(t, e)
		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "image/png", rr.Header().Get("Content-Type"), "must sniff actual bytes, not trust upstream image/jpg")
		assert.Equal(t, strconv.Itoa(len(pngBytes)), rr.Header().Get("Content-Length"))
		assert.Equal(t, []string(nil), rr.Header()["Custom-Header"], "strip all custom headers")
		assert.NotNil(t, rr.Header()["Etag"])
		// defense headers must be present on every response
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Contains(t, rr.Header().Get("Content-Disposition"), "inline")
		csp := rr.Header().Get("Content-Security-Policy")
		assert.Contains(t, csp, "default-src 'none'")
		assert.Contains(t, csp, "sandbox")

		bb := bytes.Buffer{}
		sz, e := io.Copy(&bb, rr.Body)
		assert.NoError(t, e)
		assert.Equal(t, int64(len(pngBytes)), sz)
		assert.Equal(t, pngBytes, bb.Bytes())
	}

	{
		// status 304
		req, e := http.NewRequest("GET", "/b3daa77b4c04a9551b8781d03191fe098f325e67.image", http.NoBody)
		require.NoError(t, e)
		id := p.Store.ID("b3daa77b4c04a9551b8781d03191fe098f325e67.image")
		req.Header.Add("If-None-Match", p.Store.ID(id)) // hash of `some_random_name.image` since the file doesn't exist

		rr := httptest.NewRecorder()
		handler := http.Handler(http.HandlerFunc(p.Handler))
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotModified, rr.Code)
		assert.Equal(t, []string{`"` + id + `"`}, rr.Header()["Etag"])
	}
}

func TestAvatar_WithValidPictures(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/circles.png" {
			http.ServeFile(w, r, "testdata/circles.png")
			return
		}
		if r.URL.Path == "/circles.jpg" {
			http.ServeFile(w, r, "testdata/circles.jpg")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer ts.Close()

	p := Proxy{RoutePath: "/avatar", Store: NewLocalFS("/tmp/avatars.test"), L: logger.Std}
	assert.NoError(t, os.MkdirAll("/tmp/avatars.test", 0o700))
	defer os.RemoveAll("/tmp/avatars.test")
	client := &http.Client{Timeout: time.Second}

	testCases := []struct {
		name        string
		user        token.User
		imageFile   string
		contentType string
	}{
		{
			name:        "PNG Image",
			user:        token.User{ID: "user2", Name: "user2 name", Picture: ts.URL + "/circles.png"},
			imageFile:   "testdata/circles.png",
			contentType: "image/png",
		},
		{
			name:        "JPG Image",
			user:        token.User{ID: "user3", Name: "user3 name", Picture: ts.URL + "/circles.jpg"},
			imageFile:   "testdata/circles.jpg",
			contentType: "image/jpeg",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageURL, err := p.Put(tc.user, client)
			assert.NoError(t, err)
			t.Logf("%s URL: %s", tc.name, imageURL)

			req, err := http.NewRequest("GET", imageURL, http.NoBody)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			handler := http.Handler(http.HandlerFunc(p.Handler))
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, []string{tc.contentType}, rr.Header()["Content-Type"])

			imageData, err := os.ReadFile(tc.imageFile)
			require.NoError(t, err)
			assert.Equal(t, imageData, rr.Body.Bytes())
			assert.Equal(t, []string{fmt.Sprintf("%d", len(imageData))}, rr.Header()["Content-Length"])
		})
	}
}

func TestAvatar_resize(t *testing.T) {
	checkC := func(t *testing.T, r io.Reader, cExp []byte) {
		content, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, cExp, content)
	}

	p := Proxy{L: logger.Std}
	// reader is nil.
	resizedR := p.resize(nil, 100)
	assert.Nil(t, resizedR)

	// non-image bytes (e.g. an attacker's HTML payload) must NEVER pass through, even
	// with limit <= 0: returning the raw bytes would let storage be poisoned with
	// arbitrary content that Handler() would later sniff and serve as text/html.
	assert.Nil(t, p.resize([]byte("some picture bin data"), -1),
		"non-image must be rejected regardless of limit (no pass-through)")
	assert.Nil(t, p.resize([]byte("invalid image content"), 100),
		"decode failure must return nil (no pass-through)")
	assert.Nil(t, p.resize([]byte("<html><script>alert(1)</script></html>"), 100),
		"HTML body must be rejected")

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

		// no need for resize, avatar dimensions are smaller than resize limit.
		resizedR = p.resize(img, 800)
		assert.NotNil(t, resizedR, "file %s", c.file)
		checkC(t, resizedR, img)

		// no-resize path with limit=0 must also preserve the original bytes verbatim —
		// this matters for animated GIFs and other multi-frame formats where decoding
		// via image.Decode would consume only the first frame and truncate the rest.
		resizedR = p.resize(img, 0)
		assert.NotNil(t, resizedR, "limit=0 must return original bytes for %s", c.file)
		checkC(t, resizedR, img)

		// resizing to half of width. Check resizedR avatar format PNG.
		resizedR = p.resize(img, 400)
		assert.NotNil(t, resizedR, "file %s", c.file)

		imgRz, format, err := image.Decode(resizedR)
		assert.NoError(t, err, "file %s", c.file)
		assert.Equal(t, "png", format, "file %s", c.file)
		bounds := imgRz.Bounds()
		assert.Equal(t, c.wr, bounds.Dx(), "file %s", c.file)
		assert.Equal(t, c.hr, bounds.Dy(), "file %s", c.file)
	}
}

// TestAvatar_resizeRejectsDecompressionBomb proves a tiny PNG that declares huge
// dimensions in its IHDR chunk is rejected via DecodeConfig (cheap, no allocation)
// before image.Decode is called. Without this check, image.Decode would allocate
// width*height*4 bytes of pixel memory and OOM the auth service on each login that
// fetches an attacker-controlled u.Picture.
//
// The product-overflow case (65535×65535 wraps int32) is also exercised: the guard
// must compute the product in int64 so 32-bit builds (GOARCH=386, 32-bit arm) cannot
// be tricked into letting the bomb through by integer wraparound.
func TestAvatar_resizeRejectsDecompressionBomb(t *testing.T) {
	cases := []struct {
		name   string
		w, h   uint32
		reason string
	}{
		{name: "huge square", w: 65535, h: 65535, reason: "well over maxAvatarPixels; also overflows int32 product"},
		{name: "non-square overflow", w: 70000, h: 70000, reason: "still overflows int32 product on 32-bit builds"},
		{name: "thin huge area", w: 1 << 24, h: 1 << 24, reason: "product fits int64 but exceeds maxAvatarPixels by orders of magnitude"},
	}
	p := Proxy{L: logger.Std}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bomb := makeBombPNG(c.w, c.h)
			require.Less(t, len(bomb), 100, "bomb must be small compressed — that is the threat model")
			assert.Nil(t, p.resize(bomb, 100), "limit>0: %s", c.reason)
			assert.Nil(t, p.resize(bomb, 0), "limit=0: %s", c.reason)
		})
	}
}

// makeBombPNG constructs a PNG header with an IHDR chunk declaring the given
// width/height but no IDAT body. image.DecodeConfig returns those dimensions
// without allocating pixel memory; image.Decode on the same bytes would either
// fail or attempt to allocate w*h*4 bytes.
func makeBombPNG(width, height uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8  // bit depth
	ihdr[9] = 2  // RGB color type
	ihdr[10] = 0 // compression
	ihdr[11] = 0 // filter
	ihdr[12] = 0 // interlace

	_ = binary.Write(&buf, binary.BigEndian, uint32(13)) // chunk length
	buf.WriteString("IHDR")
	buf.Write(ihdr)

	crcInput := append([]byte("IHDR"), ihdr...)
	_ = binary.Write(&buf, binary.BigEndian, crc32.ChecksumIEEE(crcInput))
	return buf.Bytes()
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
