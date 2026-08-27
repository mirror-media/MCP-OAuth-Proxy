package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mirror-media/mcp-oauth-proxy/pkg/admin"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/crypto"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/db"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/oidc"
)

func main() {
	cfg := config.Load()
	log.Printf("Starting MCP OAuth Proxy on port %s (Issuer: %s)...", cfg.Port, cfg.Issuer)

	store, err := db.Init(cfg)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	jwtManager, err := crypto.InitJWTManager(store)
	if err != nil {
		log.Fatalf("JWT Manager initialization failed: %v", err)
	}

	adminServer := admin.NewAdminServer(cfg, store)
	oidcServer := oidc.NewServer(cfg, store, jwtManager, adminServer)

	mux := http.NewServeMux()

	// Health Checks
	mux.HandleFunc("/debug/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/debug/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// OIDC & OAuth2 Endpoints
	mux.HandleFunc("/.well-known/openid-configuration", oidcServer.HandleDiscovery)
	mux.HandleFunc("/.well-known/oauth-authorization-server", oidcServer.HandleDiscovery)
	
	handleProtectedResource := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resourceURL := fmt.Sprintf("%s/mcp/sse", cfg.Issuer)
		if strings.Contains(r.URL.Path, "daily") {
			resourceURL = fmt.Sprintf("%s/daily/sse", cfg.Issuer)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resource":              resourceURL,
			"authorization_servers": []string{cfg.Issuer},
		})
	}
	mux.HandleFunc("/.well-known/oauth-protected-resource", handleProtectedResource)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", handleProtectedResource)
	mux.HandleFunc("/.well-known/jwks.json", oidcServer.HandleJWKS)
	mux.HandleFunc("/oauth/v2/keys", oidcServer.HandleJWKS)
	mux.HandleFunc("/oauth/v2/authorize", oidcServer.HandleAuthorize)
	mux.HandleFunc("/authorize", oidcServer.HandleAuthorize)
	mux.HandleFunc("/oauth/v2/login", oidcServer.HandleLoginPost)
	mux.HandleFunc("/oauth/v2/token", oidcServer.HandleToken)
	mux.HandleFunc("/token", oidcServer.HandleToken)
	mux.HandleFunc("/oauth/v2/userinfo", oidcServer.HandleUserInfo)
	mux.HandleFunc("/userinfo", oidcServer.HandleUserInfo)
	mux.HandleFunc("/oidc/v1/userinfo", oidcServer.HandleUserInfo)
	mux.HandleFunc("/oauth/v2/register", oidcServer.HandleRegister)
	mux.HandleFunc("/register", oidcServer.HandleRegister)

	// Google Workspace SSO Endpoints
	mux.HandleFunc("/auth/google/login", oidcServer.HandleGoogleLogin)
	mux.HandleFunc("/auth/google/callback", oidcServer.HandleGoogleCallback)

	// Management Console UI & Admin APIs (Protected by Auth & Admin Role Check)
	mux.HandleFunc("/ui/console/", adminServer.RequireAuth(adminServer.HandleConsoleUI))
	mux.HandleFunc("/ui/console", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/console/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/api/v1/me", adminServer.RequireAuth(adminServer.HandleMe))
	mux.HandleFunc("/api/v1/clients", adminServer.RequireAdmin(adminServer.HandleClients))
	mux.HandleFunc("/api/v1/clients/", adminServer.RequireAdmin(adminServer.HandleDeleteClient))
	mux.HandleFunc("/api/v1/users", adminServer.RequireAdmin(adminServer.HandleUsers))
	mux.HandleFunc("/api/v1/users/", adminServer.RequireAdmin(adminServer.HandleDeleteUser))

	// Unified GA & Mirror Media CMS MCP Gateway Proxy (Protected by Auth)
	gaMCPTarget, parseErr := url.Parse("https://ga-mcp-983956931553.asia-east1.run.app")
	if parseErr != nil {
		log.Fatalf("Failed to parse GA MCP Target URL: %v", parseErr)
	}
	mcpProxy := httputil.NewSingleHostReverseProxy(gaMCPTarget)
	mcpHandler := adminServer.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		sessionUser := adminServer.GetSessionUser(r)
		if sessionUser != nil {
			r.Header.Set("X-User-Email", sessionUser.Email)
			r.Header.Set("X-User-Name", sessionUser.FullName)
		}
		if strings.HasPrefix(r.URL.Path, "/mcp") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/mcp")
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		r.Host = gaMCPTarget.Host
		mcpProxy.ServeHTTP(w, r)
	})

	mux.HandleFunc("/mcp/", mcpHandler)
	mux.HandleFunc("/mcp", mcpHandler)
	mux.HandleFunc("/messages", mcpHandler)
	mux.HandleFunc("/messages/", mcpHandler)

	// Mirror Daily CMS MCP Gateway Proxy (Protected by Auth)
	dailyMCPTarget, parseErr := url.Parse("https://ga-mcp-151209114015.asia-east1.run.app")
	if parseErr != nil {
		log.Fatalf("Failed to parse Daily MCP Target URL: %v", parseErr)
	}
	dailyProxy := httputil.NewSingleHostReverseProxy(dailyMCPTarget)
	dailyHandler := adminServer.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		sessionUser := adminServer.GetSessionUser(r)
		if sessionUser != nil {
			r.Header.Set("X-User-Email", sessionUser.Email)
			r.Header.Set("X-User-Name", sessionUser.FullName)
		}
		if strings.HasPrefix(r.URL.Path, "/daily") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/daily")
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		r.Host = dailyMCPTarget.Host
		dailyProxy.ServeHTTP(w, r)
	})

	mux.HandleFunc("/daily/", dailyHandler)
	mux.HandleFunc("/daily", dailyHandler)

	// Root redirect
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/console/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Server is ready and listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server shutdown with error: %v", err)
	}
}
