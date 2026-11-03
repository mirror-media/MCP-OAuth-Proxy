package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        []string
		xRealIP    string
		remoteAddr string
		hops       int
		want       string
	}{
		{
			name: "ignores caller-set entries left of the trusted hop",
			xff:  []string{"198.51.100.7, 203.0.113.9"},
			hops: 1,
			want: "203.0.113.9",
		},
		{
			name: "counts two trusted hops behind a load balancer",
			xff:  []string{"198.51.100.7, 203.0.113.9, 192.0.2.50"},
			hops: 2,
			want: "203.0.113.9",
		},
		{
			name: "joins repeated header lines in order",
			xff:  []string{"198.51.100.7", "203.0.113.9"},
			hops: 1,
			want: "203.0.113.9",
		},
		{
			name: "rejects a value that is not an IP",
			xff:  []string{"198.51.100.7, not-an-ip"},
			hops: 1,
			want: "invalid",
		},
		{
			name: "rejects an empty trusted entry",
			xff:  []string{"198.51.100.7,"},
			hops: 1,
			want: "invalid",
		},
		{
			name:       "uses the connection address with fewer entries than hops",
			xff:        []string{"203.0.113.9"},
			remoteAddr: "192.0.2.1:1234",
			hops:       2,
			want:       "192.0.2.1",
		},
		{
			name:       "uses the connection address with zero hops",
			xff:        []string{"198.51.100.7"},
			remoteAddr: "192.0.2.1:1234",
			hops:       0,
			want:       "192.0.2.1",
		},
		{
			name:       "ignores X-Real-IP",
			xRealIP:    "198.51.100.7",
			remoteAddr: "192.0.2.1:1234",
			hops:       1,
			want:       "192.0.2.1",
		},
		{
			name: "normalizes IPv6",
			xff:  []string{"198.51.100.7, 2001:DB8::1"},
			hops: 1,
			want: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			for _, v := range tt.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if got := GetClientIP(req, tt.hops); got != tt.want {
				t.Errorf("GetClientIP(hops=%d) = %q; want %q", tt.hops, got, tt.want)
			}
		})
	}
}
