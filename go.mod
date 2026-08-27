module github.com/mirror-media/mcp-oauth-proxy

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
	golang.org/x/crypto v0.24.0
	golang.org/x/oauth2 v0.21.0
)

require cloud.google.com/go/compute/metadata v0.3.0 // indirect
