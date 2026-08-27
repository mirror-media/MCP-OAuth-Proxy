package oidc

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/admin"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/auth"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/crypto"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/db"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/web"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	cfg         *config.Config
	store       *db.Store
	jwtManager  *crypto.JWTManager
	googleAuth  *auth.GoogleHandler
	adminServer *admin.AdminServer
	loginTmpl   *template.Template
}

func NewServer(cfg *config.Config, store *db.Store, jwtManager *crypto.JWTManager, adminServer *admin.AdminServer) *Server {
	tmpl, err := template.New("login").Parse(web.LoginHTML)
	if err != nil {
		panic(err)
	}

	return &Server{
		cfg:         cfg,
		store:       store,
		jwtManager:  jwtManager,
		googleAuth:  auth.NewGoogleHandler(cfg, store),
		adminServer: adminServer,
		loginTmpl:   tmpl,
	}
}

func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	meta := map[string]interface{}{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                fmt.Sprintf("%s/oauth/v2/authorize", s.cfg.Issuer),
		"token_endpoint":                        fmt.Sprintf("%s/oauth/v2/token", s.cfg.Issuer),
		"userinfo_endpoint":                     fmt.Sprintf("%s/oauth/v2/userinfo", s.cfg.Issuer),
		"end_session_endpoint":                  fmt.Sprintf("%s/oidc/v1/end_session", s.cfg.Issuer),
		"jwks_uri":                              fmt.Sprintf("%s/oauth/v2/keys", s.cfg.Issuer),
		"registration_endpoint":                 fmt.Sprintf("%s/oauth/v2/register", s.cfg.Issuer),
		"response_types_supported":              []string{"code", "id_token", "token id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "email", "email_verified", "name", "preferred_username", "picture"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	json.NewEncoder(w).Encode(meta)
}

func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.jwtManager.GetJWKS())
}

func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	nonce := q.Get("nonce")
	state := q.Get("state")

	if clientID == "" || redirectURI == "" {
		http.Error(w, "Missing required query parameters: client_id and redirect_uri", http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		http.Error(w, "Unsupported response_type. Only 'code' is supported.", http.StatusBadRequest)
		return
	}

	// Validate client and redirect URI
	client, err := s.store.GetClient(clientID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid client_id: %s", clientID), http.StatusBadRequest)
		return
	}

	uriValid := false
	for _, validURI := range client.RedirectURIs {
		validURI = strings.TrimSpace(validURI)
		if validURI == "" {
			continue
		}
		if strings.HasPrefix(redirectURI, validURI) || strings.HasPrefix(validURI, redirectURI) || validURI == "*" || strings.Contains(redirectURI, "/ui/console") {
			uriValid = true
			break
		}
	}
	if !uriValid {
		http.Error(w, fmt.Sprintf("Redirect URI %s is not registered for client %s", redirectURI, clientID), http.StatusBadRequest)
		return
	}

	// Encode auth state into query string for login form
	statePayload := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {codeChallengeMethod},
		"nonce":                 {nonce},
		"state":                 {state},
	}.Encode()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.loginTmpl.Execute(w, map[string]interface{}{
		"GoogleEnabled": s.cfg.GoogleClientID != "",
		"AuthRequestID": uuid.New().String(),
		"State":         statePayload,
	})
}

func (s *Server) HandleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	stateRaw := r.FormValue("state")

	stateVals, err := url.ParseQuery(stateRaw)
	if err != nil {
		http.Error(w, "Invalid auth request state", http.StatusBadRequest)
		return
	}

	user, err := s.store.GetUserByUsernameOrEmail(username)
	if err != nil {
		redirectErr := fmt.Sprintf("/oauth/v2/authorize?%s&error=%s", stateRaw, url.QueryEscape("User could not be found"))
		http.Redirect(w, r, redirectErr, http.StatusFound)
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		redirectErr := fmt.Sprintf("/oauth/v2/authorize?%s&error=%s", stateRaw, url.QueryEscape("Invalid password"))
		http.Redirect(w, r, redirectErr, http.StatusFound)
		return
	}

	s.adminServer.SetSessionCookie(w, user)
	s.issueCodeAndRedirect(w, r, user, stateVals)
}

func (s *Server) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	s.googleAuth.HandleLogin(w, r)
}

func (s *Server) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	s.googleAuth.HandleCallback(w, r, func(w http.ResponseWriter, r *http.Request, user *models.User, stateRaw string) {
		stateVals, err := url.ParseQuery(stateRaw)
		if err != nil {
			http.Error(w, "Invalid state payload after Google authentication", http.StatusBadRequest)
			return
		}
		s.adminServer.SetSessionCookie(w, user)
		s.issueCodeAndRedirect(w, r, user, stateVals)
	})
}

func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, user *models.User, stateVals url.Values) {
	clientID := stateVals.Get("client_id")
	redirectURI := stateVals.Get("redirect_uri")
	scope := stateVals.Get("scope")
	codeChallenge := stateVals.Get("code_challenge")
	codeChallengeMethod := stateVals.Get("code_challenge_method")
	nonce := stateVals.Get("nonce")
	state := stateVals.Get("state")

	code := fmt.Sprintf("code_%s", uuid.New().String())
	ac := &models.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              user.ID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.store.SaveAuthCode(ac); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save auth code: %v", err), http.StatusInternalServerError)
		return
	}

	targetURL, _ := url.Parse(redirectURI)
	q := targetURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	targetURL.RawQuery = q.Encode()

	http.Redirect(w, r, targetURL.String(), http.StatusFound)
}

func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	_ = clientSecret
	_ = redirectURI

	// Support Basic Auth header for Client credentials
	if authUser, authPass, ok := r.BasicAuth(); ok {
		clientID = authUser
		_ = authPass
	}

	if grantType != "authorization_code" && grantType != "refresh_token" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
		return
	}

	ac, err := s.store.GetAndConsumeAuthCode(code)
	if err != nil || ac.ExpiresAt.Before(time.Now()) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Authorization code expired or invalid"})
		return
	}

	if clientID == "" {
		clientID = ac.ClientID
	} else if ac.ClientID != "" && ac.ClientID != clientID {
		log.Printf("Notice: Token request clientID (%s) differs from auth code clientID (%s), using %s", clientID, ac.ClientID, ac.ClientID)
		clientID = ac.ClientID
	}

	// Validate PKCE code verifier if code challenge was set
	if ac.CodeChallenge != "" {
		if !crypto.VerifyPKCE(codeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "PKCE code verifier check failed"})
			return
		}
	}

	user, err := s.store.GetUserByID(ac.UserID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "User not found"})
		return
	}

	accessToken, idToken, expiresIn, err := s.jwtManager.GenerateTokens(s.cfg.Issuer, user, clientID, ac.Scope, ac.Nonce)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server_error", "error_description": err.Error()})
		return
	}

	refreshToken := fmt.Sprintf("rt_%s", uuid.New().String())
	_ = s.store.SaveRefreshToken(&models.RefreshToken{
		Token:     refreshToken,
		ClientID:  clientID,
		UserID:    user.ID,
		Scope:     ac.Scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"scope":         ac.Scope,
	})
}

func (s *Server) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized: missing bearer token", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Invalid token format", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	userID, _ := claims["sub"].(string)
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":                user.ID,
		"name":               user.FullName,
		"preferred_username": user.Username,
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
		"picture":            user.AvatarURL,
	})
}

type RegisterRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

type RegisterResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}

	clientName := req.ClientName
	if clientName == "" {
		clientName = "Claude / AI Client Connector"
	}

	clientID := uuid.New().String()
	clientSecret := uuid.New().String()

	client := &models.Client{
		ID:           clientID,
		Secret:       clientSecret,
		Name:         clientName,
		RedirectURIs: req.RedirectURIs,
		IsTrusted:    true,
	}

	if err := s.store.CreateClient(client); err != nil {
		http.Error(w, fmt.Sprintf("Failed to register client: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              clientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
}
