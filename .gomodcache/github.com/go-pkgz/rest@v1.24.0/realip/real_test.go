package realip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		wantIP     string
		wantErr    bool
	}{
		// x-Real-IP tests (highest priority)
		{name: "X-Real-IP public", headers: map[string]string{"X-Real-IP": "8.8.8.8"}, wantIP: "8.8.8.8"},
		{name: "X-Real-IP with spaces", headers: map[string]string{"X-Real-IP": "  8.8.8.8  "}, wantIP: "8.8.8.8"},
		{name: "X-Real-IP private falls through", remoteAddr: "1.2.3.4:1234",
			headers: map[string]string{"X-Real-IP": "192.168.1.1"}, wantIP: "1.2.3.4"},
		{name: "X-Real-IP loopback falls through", remoteAddr: "1.2.3.4:1234",
			headers: map[string]string{"X-Real-IP": "127.0.0.1"}, wantIP: "1.2.3.4"},
		{name: "X-Real-IP IPv6 public", headers: map[string]string{"X-Real-IP": "2001:db8::1"}, wantIP: "2001:db8::1"},
		{name: "X-Real-IP IPv6 loopback falls through", remoteAddr: "1.2.3.4:1234",
			headers: map[string]string{"X-Real-IP": "::1"}, wantIP: "1.2.3.4"},
		{name: "X-Real-IP IPv6 link-local falls through", remoteAddr: "1.2.3.4:1234",
			headers: map[string]string{"X-Real-IP": "fe80::1"}, wantIP: "1.2.3.4"},

		// CF-Connecting-IP tests (second priority)
		{name: "CF-Connecting-IP public", headers: map[string]string{"CF-Connecting-IP": "8.8.8.8"}, wantIP: "8.8.8.8"},
		{name: "CF-Connecting-IP private falls through", remoteAddr: "1.2.3.4:1234",
			headers: map[string]string{"CF-Connecting-IP": "10.0.0.1"}, wantIP: "1.2.3.4"},
		{name: "CF-Connecting-IP IPv6 public", headers: map[string]string{"CF-Connecting-IP": "2001:db8::1"}, wantIP: "2001:db8::1"},

		// x-Forwarded-For tests (third priority, leftmost public)
		{name: "XFF single public", headers: map[string]string{"X-Forwarded-For": "8.8.8.8"}, wantIP: "8.8.8.8"},
		{name: "XFF multiple public returns leftmost", headers: map[string]string{"X-Forwarded-For": "8.8.8.8, 1.1.1.1, 30.30.30.1"}, wantIP: "8.8.8.8"},
		{name: "XFF private first skipped", headers: map[string]string{"X-Forwarded-For": "192.168.1.1, 8.8.8.8"}, wantIP: "8.8.8.8"},
		{name: "XFF multiple private skipped", headers: map[string]string{"X-Forwarded-For": "192.168.1.1, 10.0.0.1, 8.8.8.8"}, wantIP: "8.8.8.8"},
		{name: "XFF all private falls through", remoteAddr: "1.2.3.4:1234",
			headers: map[string]string{"X-Forwarded-For": "192.168.1.1, 10.0.0.65"}, wantIP: "1.2.3.4"},
		{name: "XFF IPv6 public", headers: map[string]string{"X-Forwarded-For": "2001:db8::1"}, wantIP: "2001:db8::1"},
		{name: "XFF IPv6 mixed", headers: map[string]string{"X-Forwarded-For": "::1, fc00::1, 2001:db8::1"}, wantIP: "2001:db8::1"},
		{name: "XFF invalid entries skipped", headers: map[string]string{"X-Forwarded-For": "not-an-ip, 8.8.8.8, garbage"}, wantIP: "8.8.8.8"},

		// header priority tests
		{name: "X-Real-IP takes priority over XFF", headers: map[string]string{"X-Real-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"}, wantIP: "1.2.3.4"},
		{name: "X-Real-IP takes priority over CF-Connecting-IP", headers: map[string]string{"X-Real-IP": "1.2.3.4", "CF-Connecting-IP": "5.6.7.8"}, wantIP: "1.2.3.4"},
		{name: "CF-Connecting-IP takes priority over XFF", headers: map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"}, wantIP: "1.2.3.4"},
		{name: "private X-Real-IP falls to public CF-Connecting-IP",
			headers: map[string]string{"X-Real-IP": "192.168.1.1", "CF-Connecting-IP": "5.6.7.8"}, wantIP: "5.6.7.8"},
		{name: "private X-Real-IP and CF-Connecting-IP falls to XFF",
			headers: map[string]string{"X-Real-IP": "192.168.1.1", "CF-Connecting-IP": "10.0.0.1", "X-Forwarded-For": "5.6.7.8"}, wantIP: "5.6.7.8"},

		// cloudflare CDN scenario
		{name: "Cloudflare chain leftmost is client", headers: map[string]string{"X-Forwarded-For": "203.0.113.195, 172.70.231.89"}, wantIP: "203.0.113.195"},
		{name: "Cloudflare with CF-Connecting-IP", headers: map[string]string{"CF-Connecting-IP": "203.0.113.195", "X-Forwarded-For": "203.0.113.195, 172.70.231.89"}, wantIP: "203.0.113.195"},

		// RemoteAddr fallback tests
		{name: "RemoteAddr IPv4 with port", remoteAddr: "192.0.2.1:1234", wantIP: "192.0.2.1"},
		{name: "RemoteAddr IPv4 without port", remoteAddr: "127.0.0.1", wantIP: "127.0.0.1"},
		{name: "RemoteAddr IPv6 with port", remoteAddr: "[2001:db8::1]:1234", wantIP: "2001:db8::1"},
		{name: "RemoteAddr IPv6 without port", remoteAddr: "::1", wantIP: "::1"},
		{name: "RemoteAddr invalid", remoteAddr: "invalid-ip", wantErr: true},
		{name: "RemoteAddr empty", remoteAddr: "", wantErr: true},
		{name: "no headers no RemoteAddr", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", http.NoBody)
			require.NoError(t, err)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			gotIP, err := Get(req)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, gotIP)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantIP, gotIP)
		})
	}
}

func TestGetFromRemoteAddr(t *testing.T) {
	var handlerErr error
	var handlerIP string

	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerIP, handlerErr = Get(r)
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/something", http.NoBody)
	require.NoError(t, err)
	client := http.Client{Timeout: time.Second}
	_, err = client.Do(req)
	require.NoError(t, err)

	require.NoError(t, handlerErr)
	assert.Equal(t, "127.0.0.1", handlerIP)
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		public bool
	}{
		// public IPv4
		{name: "public 8.8.8.8", ip: "8.8.8.8", public: true},
		{name: "public 1.1.1.1", ip: "1.1.1.1", public: true},
		{name: "public 203.0.113.1", ip: "203.0.113.1", public: true},

		// private IPv4
		{name: "private 10.x", ip: "10.0.0.1", public: false},
		{name: "private 172.16.x", ip: "172.16.0.1", public: false},
		{name: "private 172.31.x", ip: "172.31.255.255", public: false},
		{name: "private 192.168.x", ip: "192.168.1.1", public: false},

		// private range boundaries
		{name: "boundary 172.15.255.255 public", ip: "172.15.255.255", public: true},
		{name: "boundary 172.32.0.0 public", ip: "172.32.0.0", public: true},
		{name: "boundary 100.63.255.255 public", ip: "100.63.255.255", public: true},
		{name: "boundary 100.128.0.0 public", ip: "100.128.0.0", public: true},

		// special IPv4
		{name: "loopback", ip: "127.0.0.1", public: false},
		{name: "link-local 169.254.x", ip: "169.254.1.1", public: false},
		{name: "shared RFC6598", ip: "100.64.0.1", public: false},
		{name: "benchmarking RFC2544", ip: "198.18.0.1", public: false},

		// public IPv6
		{name: "public IPv6", ip: "2001:db8::1", public: true},
		{name: "public IPv6 full", ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", public: true},

		// private/special IPv6
		{name: "IPv6 loopback", ip: "::1", public: false},
		{name: "IPv6 ULA fc00::", ip: "fc00::1", public: false},
		{name: "IPv6 ULA fd00::", ip: "fd00::1", public: false},
		{name: "IPv6 link-local", ip: "fe80::1", public: false},

		// edge cases
		{name: "nil IP", ip: "", public: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}
			assert.Equal(t, tt.public, isPublicIP(ip))
		})
	}
}
