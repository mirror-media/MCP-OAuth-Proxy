package admin

import "strings"

const protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// MCPResourcePath maps both MCP gateway requests and RFC 9728 metadata paths
// to the OAuth resource identifier used for that transport.
func MCPResourcePath(requestPath string) string {
	path := strings.TrimPrefix(requestPath, protectedResourceMetadataPath)

	switch {
	case strings.HasPrefix(path, "/mcp/sse"):
		return "/mcp/sse"
	case path == "/mcp" || strings.HasPrefix(path, "/mcp/"):
		return "/mcp"
	case strings.HasPrefix(path, "/daily"):
		return "/daily/sse"
	default:
		// Preserve the legacy Claude resource for generic metadata discovery and
		// for the separate /messages endpoint used by SSE sessions.
		return "/mcp/sse"
	}
}

func (a *AdminServer) MCPResourceURL(requestPath string) string {
	return strings.TrimRight(a.cfg.Issuer, "/") + MCPResourcePath(requestPath)
}

func (a *AdminServer) MCPResourceMetadataURL(requestPath string) string {
	return strings.TrimRight(a.cfg.Issuer, "/") + protectedResourceMetadataPath + MCPResourcePath(requestPath)
}
