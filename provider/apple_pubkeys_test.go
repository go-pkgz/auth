package provider

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplePublicKey_Fetch(t *testing.T) {
	teardown := prepareAppleKeysTestServer(t, 8982)

	defer teardown()

	// valid response checking
	ctx := context.Background()
	url := fmt.Sprintf("http://127.0.0.1:%d/keys", 8982)
	set, err := fetchAppleJWK(ctx, url)
	assert.NoError(t, err)
	assert.NotEqual(t, appleKeySet{}, set)

	// check service response error
	url = fmt.Sprintf("http://127.0.0.1:%d/error", 8982)
	_, err = fetchAppleJWK(ctx, url)
	assert.Error(t, err)

	url = fmt.Sprintf("http://127.0.0.1:%d/no-answer", 8982)
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	_, err = fetchAppleJWK(ctx, url)
	defer cancelFunc()
	assert.Error(t, err)

}

func TestParseAppleJWK(t *testing.T) {
	testKeys := `{
					"keys": [
					{
					  "kty": "RSA",
					  "kid": "86D88Kf",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
					  "e": "AQAB"
					},
					{
					  "kty": "RSA",
					  "kid": "eXaunmL",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
					  "e": "AQAB"
					},
					{
					  "kty": "RSA",
					  "kid": "YuyXoY",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
					  "e": "AQAB"
					}
				  ]
				}`
	testKeySet, err := parseAppleJWK([]byte(testKeys))
	assert.NoError(t, err)

	key, err := testKeySet.get("YuyXoY")
	assert.NoError(t, err)
	assert.Equal(t, key.ID, "YuyXoY")

	testKeySet = appleKeySet{} // reset previous value
	testKeySet, err = parseAppleJWK([]byte(`{"keys":[]}`))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(testKeySet.keys))

	testKeySet = appleKeySet{} // reset previous value
	testKeySet, err = parseAppleJWK([]byte(`{"keys":[{
					  "kty": "RSA",
					  "kid": "86D88Kf",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "invalid-value",
					  "e": "invalid-value"
					}]}`))
	assert.Error(t, err, fmt.Errorf("failed to decode Apple public key modulus (n)"))

	testKeySet, err = parseAppleJWK([]byte(`{"keys":[{
					  "kty": "RSA",
					  "kid": "86D88Kf",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
					  "e": "invalid-value"
					}]}`))

	assert.Error(t, err, fmt.Errorf("failed to decode Apple public key modulus (e)"))
	testKeySet, err = parseAppleJWK([]byte(`{invalid-json}`))
	assert.Error(t, err)
}

func TestAppleKeySet_Get(t *testing.T) {
	testKeySet := appleKeySet{}
	_, err := testKeySet.get("some-kid")
	assert.Error(t, err, "failed to get key in appleKeySet, key set is nil or empty")

	testKeySet, err = parseAppleJWK([]byte(`{"keys":[{
					  "kty": "RSA",
					  "kid": "86D88Kf",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
					  "e": "AQAB"
					}]}`))
	require.Nil(t, err)

	apk, err := testKeySet.get("86D88Kf")
	assert.NoError(t, err)
	assert.Equal(t, apk.ID, "86D88Kf")

	_, err = testKeySet.get("not-found-kid")
	assert.Error(t, err, "key with ID some-kid not found")

}

func TestAppleKeySet_KeyFunc(t *testing.T) {

	tokenHdr := map[string]interface{}{"kid": "86D88Kf"}
	validToken := jwt.Token{Header: tokenHdr}
	testKeySet, err := parseAppleJWK([]byte(`{"keys":[{
					  "kty": "RSA",
					  "kid": "86D88Kf",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
					  "e": "AQAB"
					}]}`))
	require.Nil(t, err)
	assert.IsType(t, appleKeySet{}, testKeySet)
	_, err = testKeySet.keyFunc(&validToken)
	assert.NoError(t, err)

	testKeySet, err = parseAppleJWK([]byte(`{"keys":[{
					  "kty": "RSA",
					  "kid": "eXaunmL",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
					  "e": "AQAB"
					}]}`))
	require.NoError(t, err)
	assert.NotNil(t, testKeySet)

	_, err = testKeySet.keyFunc(&validToken)
	assert.Error(t, err, "key with ID 86D88Kf not found")

	_, err = testKeySet.keyFunc(&jwt.Token{})
	assert.Error(t, err, "get JWT kid header not found")
}

//nolint:gosec //this is a test, we don't care about ReadHeaderTimeout
func prepareAppleKeysTestServer(t *testing.T, authPort int) func() {
	ts := &http.Server{
		Addr: fmt.Sprintf(":%d", authPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[MOCK APPLE KEYS SERVER] request %s %s %+v", r.Method, r.URL, r.Header)
			switch {
			case strings.HasPrefix(r.URL.Path, "/keys"):

				testKeys := `{
					"keys": [
					{
					  "kty": "RSA",
					  "kid": "86D88Kf",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
					  "e": "AQAB"
					},
					{
					  "kty": "RSA",
					  "kid": "eXaunmL",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
					  "e": "AQAB"
					},
					{
					  "kty": "RSA",
					  "kid": "YuyXoY",
					  "use": "sig",
					  "alg": "RS256",
					  "n": "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
					  "e": "AQAB"
					}
				  ]
				}`
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err := w.Write([]byte(testKeys))
				assert.NoError(t, err)
			case strings.HasPrefix(r.URL.Path, "/error"):
				_, err := w.Write([]byte("test error"))
				assert.NoError(t, err)
			case strings.HasPrefix(r.URL.Path, "/no-answer"):
				time.Sleep(time.Second * 3)
				return
			default:
				t.Fatalf("unexpected oauth request %s %s", r.Method, r.URL)
			}
		}),
	}

	go func() { _ = ts.ListenAndServe() }()

	time.Sleep(time.Millisecond * 100) // let them start

	return func() {
		assert.NoError(t, ts.Close())
	}
}
