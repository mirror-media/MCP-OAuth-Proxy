package config

import "testing"

func TestLoadTrustedProxyHops(t *testing.T) {
	tests := map[string]int{
		"":   1,
		"0":  0,
		"2":  2,
		"-1": 1,
		"x":  1,
	}
	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXY_HOPS", value)
			if got := Load().TrustedProxyHops; got != want {
				t.Errorf("TRUSTED_PROXY_HOPS=%q: TrustedProxyHops = %d; want %d", value, got, want)
			}
		})
	}
}
