package main

import "testing"

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
