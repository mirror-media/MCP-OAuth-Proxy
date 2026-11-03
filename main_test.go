package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirror-media/mcp-oauth-proxy/pkg/admin"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
)

func TestRewriteGAMCPPath(t *testing.T) {
	tests := map[string]string{
		"/mcp/sse":          "/sse",
		"/mcp/sse/":         "/sse/",
		"/mcp/sse/anything": "/sse/anything",
		"/mcp":              "/mcp",
		"/mcp/":             "/mcp/",
		"/messages":         "/messages",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := rewriteGAMCPPath(input); got != want {
				t.Fatalf("rewriteGAMCPPath(%q) = %q; want %q", input, got, want)
			}
		})
	}
}

// serveLogged runs one request through loggingMiddleware and returns the
// access log output and the value the middleware panicked with, if any.
func serveLogged(t *testing.T, h http.HandlerFunc) (string, interface{}) {
	t.Helper()
	var buf bytes.Buffer
	prev := accessLog.Writer()
	accessLog.SetOutput(&buf)
	t.Cleanup(func() { accessLog.SetOutput(prev) })

	adminServer := admin.NewAdminServer(&config.Config{}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse?x=1", nil)
	var panicked interface{}
	func() {
		defer func() { panicked = recover() }()
		loggingMiddleware(h, adminServer).ServeHTTP(httptest.NewRecorder(), req)
	}()
	return buf.String(), panicked
}

func parseAccessLine(t *testing.T, out string) map[string]interface{} {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly one access log line, got %q", out)
	}
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("access log line is not JSON: %v: %q", err, lines[0])
	}
	return entry
}

func TestLoggingMiddleware_WritesJSONLine(t *testing.T) {
	out, panicked := serveLogged(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	if panicked != nil {
		t.Fatalf("unexpected panic: %v", panicked)
	}
	entry := parseAccessLine(t, out)
	if entry["event"] != "http_access" || entry["status"] != float64(http.StatusTeapot) || entry["severity"] != "WARNING" {
		t.Errorf("unexpected entry: %v", entry)
	}
	if _, ok := entry["aborted"]; ok {
		t.Errorf("aborted set on a completed request: %v", entry)
	}
}

func TestLoggingMiddleware_LogsAbortedRequestAndRepanics(t *testing.T) {
	out, panicked := serveLogged(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler)
	})
	if panicked != http.ErrAbortHandler {
		t.Fatalf("panic value = %v, want http.ErrAbortHandler", panicked)
	}
	entry := parseAccessLine(t, out)
	if entry["aborted"] != true || entry["path"] != "/mcp/sse" {
		t.Errorf("unexpected entry: %v", entry)
	}
}
