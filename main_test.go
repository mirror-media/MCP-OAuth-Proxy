package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
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

func TestForwardToMCP_SendsOnlyDerivedClientIP(t *testing.T) {
	var gotXFF []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Values("X-Forwarded-For")
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AdminUsername: "admin", AdminPassword: "pw", TrustedProxyHops: 1}
	adminServer := admin.NewAdminServer(cfg, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.SetBasicAuth("admin", "pw")
	req.Header.Add("X-Forwarded-For", "198.51.100.7, 203.0.113.9")

	forwardToMCP(httptest.NewRecorder(), req, adminServer, httputil.NewSingleHostReverseProxy(target), target.Host)

	want := []string{"203.0.113.9, 192.0.2.1"}
	if strings.Join(gotXFF, "|") != strings.Join(want, "|") {
		t.Errorf("upstream X-Forwarded-For = %q; want %q", gotXFF, want)
	}
}

func TestLoggingMiddleware_LogsClientIPFromInboundHeader(t *testing.T) {
	var buf bytes.Buffer
	prev := accessLog.Writer()
	accessLog.SetOutput(&buf)
	t.Cleanup(func() { accessLog.SetOutput(prev) })

	adminServer := admin.NewAdminServer(&config.Config{TrustedProxyHops: 1}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Add("X-Forwarded-For", "198.51.100.7, 203.0.113.9")
	h := func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-For", "192.0.2.99")
	}
	loggingMiddleware(http.HandlerFunc(h), adminServer).ServeHTTP(httptest.NewRecorder(), req)

	entry := parseAccessLine(t, buf.String())
	if entry["client_ip"] != "203.0.113.9" || entry["x_forwarded_for"] != "198.51.100.7, 203.0.113.9" {
		t.Errorf("unexpected entry: %v", entry)
	}
}
