package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRest_RenderJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j := JSON{"key1": 1, "key2": "222"}
		RenderJSON(w, j)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, `{"key1":1,"key2":"222"}`+"\n", string(body))
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
}

func TestRest_RenderJSONFromBytes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, RenderJSONFromBytes(w, r, []byte("some data")))
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "some data", string(body))
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
}

func TestRest_RenderJSONWithHTML(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j := JSON{"key1": "val1", "key2": 2.0, "html": `<div> blah </div>`}
		require.NoError(t, RenderJSONWithHTML(w, r, j))
	}))
	defer ts.Close()

	j1 := JSON{"key1": "val1", "key2": 2.0, "html": `<div> blah </div>`}

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	defer resp.Body.Close()
	j2 := JSON{}
	err = json.Unmarshal(body, &j2)
	require.NoError(t, err)

	assert.Equal(t, j1, j2)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
}

func TestParseFromTo(t *testing.T) {
	tbl := []struct {
		query    string
		from, to time.Time
		err      error
	}{
		{
			query: "from=20220406&to=20220501",
			from:  time.Date(2022, time.April, 6, 0, 0, 0, 0, time.UTC),
			to:    time.Date(2022, time.May, 1, 0, 0, 0, 0, time.UTC),
			err:   nil,
		},
		{
			query: "from=2022-04-06T18:30:25&to=2022-05-01T17:50",
			from:  time.Date(2022, time.April, 6, 18, 30, 25, 0, time.UTC),
			to:    time.Date(2022, time.May, 1, 17, 50, 0, 0, time.UTC),
			err:   nil,
		},
		{
			query: "from=2022-04-06T18:30:25&to=xyzbad",
			err:   errors.New(`incorrect to time: can't parse date "xyzbad"`),
		},
		{
			query: "from=123455&to=2022-05-01T17:50",
			err:   errors.New(`incorrect from time: can't parse date "123455"`),
		},
		{"", time.Time{}, time.Time{}, errors.New("incorrect from time: can't parse date \"\"")},
	}

	for i, tt := range tbl {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://localhost?"+tt.query, http.NoBody)
			require.NoError(t, err)
			from, to, err := ParseFromTo(req)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.from, from)
			assert.Equal(t, tt.to, to)
		})
	}

}

func TestDecodeJSONRequest(t *testing.T) {
	type record struct {
		Field1 string `json:"field1"`
		Field2 int    `json:"field2"`
	}

	inp := `{"field1":"value1","field2":2}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(inp))
	req.Header.Set("Content-Type", "application/json")

	var obj record
	err := DecodeJSON(req, &obj)
	require.NoError(t, err)
	assert.Equal(t, "value1", obj.Field1)
	assert.Equal(t, 2, obj.Field2)
}

func TestEncodeJSONResponse(t *testing.T) {
	type record struct {
		Field1 string `json:"field1"`
		Field2 int    `json:"field2"`
	}

	obj := record{Field1: "value1", Field2: 2}
	w := httptest.NewRecorder()
	if err := EncodeJSON(w, http.StatusOK, obj); err != nil {
		t.Errorf("Failed to encode JSON response: %v", err)
	}

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var decodedObj record
	err := json.NewDecoder(resp.Body).Decode(&decodedObj)
	require.NoError(t, err)

	assert.Equal(t, obj.Field1, decodedObj.Field1)
	assert.Equal(t, obj.Field2, decodedObj.Field2)
}

func TestRest_RenderJSON_EncodingError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// channels cannot be encoded to JSON
		RenderJSON(w, make(chan int))
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRest_RenderJSONWithHTML_EncodingError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// channels cannot be encoded to JSON
		err := RenderJSONWithHTML(w, r, make(chan int))
		assert.Error(t, err)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDecodeJSON_MalformedJSON(t *testing.T) {
	type record struct {
		Field1 string `json:"field1"`
	}

	inp := `{"field1": invalid}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(inp))
	req.Header.Set("Content-Type", "application/json")

	var obj record
	err := DecodeJSON(req, &obj)
	assert.Error(t, err)
}

func TestEncodeJSON_EncodingError(t *testing.T) {
	w := httptest.NewRecorder()
	// channels cannot be encoded to JSON
	err := EncodeJSON(w, http.StatusOK, make(chan int))
	assert.Error(t, err)

	// nothing was committed, so the caller can still answer with an error
	assert.Empty(t, w.Body.String())
	assert.Empty(t, w.Header().Get("Content-Type"))
	http.Error(w, "oops", http.StatusInternalServerError)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func getTestHandlerBlah() http.HandlerFunc {
	fn := func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("blah"))
	}
	return fn
}

// failingWriter fails on Write, mimicking a client that disconnected mid-response
type failingWriter struct {
	http.ResponseWriter
	err error
}

func (f *failingWriter) Write([]byte) (int, error) { return 0, f.err }

func TestEncodeJSON_WriteError(t *testing.T) {
	wantErr := errors.New("connection reset")
	w := &failingWriter{ResponseWriter: httptest.NewRecorder(), err: wantErr}

	err := EncodeJSON(w, http.StatusOK, JSON{"key": "value"})
	require.Error(t, err, "a failed write has to reach the caller")
	assert.ErrorIs(t, err, wantErr)
}
