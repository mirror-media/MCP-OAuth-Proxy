package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
)

func TestMCPResourcePath(t *testing.T) {
	tests := map[string]string{
		"/.well-known/oauth-protected-resource":           "/mcp/sse",
		"/.well-known/oauth-protected-resource/mcp/sse":   "/mcp/sse",
		"/.well-known/oauth-protected-resource/mcp":       "/mcp",
		"/.well-known/oauth-protected-resource/daily/sse": "/daily/sse",
		"/mcp/sse":   "/mcp/sse",
		"/mcp":       "/mcp",
		"/mcp/":      "/mcp",
		"/messages":  "/mcp/sse",
		"/daily/sse": "/daily/sse",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := MCPResourcePath(input); got != want {
				t.Fatalf("MCPResourcePath(%q) = %q; want %q", input, got, want)
			}
		})
	}
}

func TestRequireAuthAdvertisesTransportSpecificMetadata(t *testing.T) {
	server := &AdminServer{
		cfg: &config.Config{Issuer: "https://sso.example.test"},
	}
	next := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unauthenticated request reached protected handler")
	}

	for _, resourcePath := range []string{"/mcp", "/mcp/sse"} {
		t.Run(resourcePath, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, resourcePath, nil)
			response := httptest.NewRecorder()

			server.RequireAuth(next)(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want %d", response.Code, http.StatusUnauthorized)
			}
			want := "resource_metadata=\"https://sso.example.test/.well-known/oauth-protected-resource" + resourcePath + "\""
			if header := response.Header().Get("WWW-Authenticate"); !strings.Contains(header, want) {
				t.Fatalf("WWW-Authenticate = %q; want it to contain %q", header, want)
			}
		})
	}
}
