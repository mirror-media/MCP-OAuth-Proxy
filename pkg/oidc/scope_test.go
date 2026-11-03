package oidc

import "testing"

func TestGrantedScope(t *testing.T) {
	tests := map[string]string{
		"openid":                           "openid",
		"openid email profile":             "openid email profile",
		"admin":                            "",
		"openid admin":                     "openid",
		"xadminx":                          "",
		"openid notadmin":                  "openid",
		"  openid   openid offline_access": "openid offline_access",
		"":                                 "",
	}
	for requested, want := range tests {
		if got := grantedScope(requested); got != want {
			t.Errorf("grantedScope(%q) = %q, want %q", requested, got, want)
		}
	}
}
