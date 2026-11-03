package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/admin"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/crypto"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/db"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
)

// newTestServer connects to the Postgres database named by OAUTH_PROXY_TEST_DB
// (other connection settings come from the usual DB_* variables). The schema is
// created and seeded, so point it at a disposable database only.
func newTestServer(t *testing.T) (*Server, *db.Store) {
	t.Helper()
	name := os.Getenv("OAUTH_PROXY_TEST_DB")
	if name == "" {
		t.Skip("OAUTH_PROXY_TEST_DB not set")
	}
	t.Setenv("DB_NAME", name)
	cfg := config.Load()
	cfg.Issuer = "https://sso.example.test"
	store, err := db.Init(cfg)
	if err != nil {
		t.Fatalf("db init: %v", err)
	}
	jm, err := crypto.InitJWTManager(store)
	if err != nil {
		t.Fatalf("jwt manager: %v", err)
	}
	return NewServer(cfg, store, jm, admin.NewAdminServer(cfg, store, jm)), store
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

func postToken(t *testing.T, s *Server, form url.Values) (int, tokenResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.HandleToken(rec, req)
	var tr tokenResponse
	json.Unmarshal(rec.Body.Bytes(), &tr)
	return rec.Code, tr
}

func TestHandleToken_RefreshTokenGrant(t *testing.T) {
	s, store := newTestServer(t)

	suffix := uuid.New().String()[:8]
	user := &models.User{
		ID:            "usr_test_" + suffix,
		Username:      "refresh_" + suffix,
		Email:         fmt.Sprintf("refresh_%s@example.test", suffix),
		EmailVerified: true,
		Provider:      "google",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { store.DeleteUser(user.ID) })

	const clientID = "client_refresh_test"
	code := "code_" + uuid.New().String()
	if err := store.SaveAuthCode(&models.AuthCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      user.ID,
		RedirectURI: "http://127.0.0.1/cb",
		Scope:       "openid email",
		ExpiresAt:   time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("save auth code: %v", err)
	}

	status, first := postToken(t, s, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}})
	if status != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("authorization_code grant: status=%d error=%q", status, first.Error)
	}

	status, wrongClient := postToken(t, s, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}, "client_id": {"other_client"}})
	if status != http.StatusBadRequest || wrongClient.Error != "invalid_grant" {
		t.Fatalf("refresh with another client_id: status=%d error=%q, want 400 invalid_grant", status, wrongClient.Error)
	}

	// The mismatched attempt consumed the token; issue a fresh one for the rest.
	rt := "rt_" + uuid.New().String()
	if err := store.SaveRefreshToken(&models.RefreshToken{Token: rt, ClientID: clientID, UserID: user.ID, Scope: "openid email", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}

	status, refreshed := postToken(t, s, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}})
	if status != http.StatusOK {
		t.Fatalf("refresh_token grant: status=%d error=%q", status, refreshed.Error)
	}
	if refreshed.Scope != "openid email" {
		t.Errorf("scope = %q, want %q", refreshed.Scope, "openid email")
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == rt {
		t.Errorf("expected a new refresh token, got %q", refreshed.RefreshToken)
	}
	claims, err := s.jwtManager.VerifyToken(refreshed.AccessToken)
	if err != nil {
		t.Fatalf("refreshed access token does not verify: %v", err)
	}
	if claims["sub"] != user.ID || claims["client_id"] != clientID {
		t.Errorf("claims sub=%v client_id=%v, want %s %s", claims["sub"], claims["client_id"], user.ID, clientID)
	}

	if status, _ := postToken(t, s, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}}); status != http.StatusBadRequest {
		t.Errorf("reusing a consumed refresh token: status=%d, want 400", status)
	}

	expired := "rt_" + uuid.New().String()
	if err := store.SaveRefreshToken(&models.RefreshToken{Token: expired, ClientID: clientID, UserID: user.ID, Scope: "openid", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}
	if status, _ := postToken(t, s, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {expired}, "client_id": {clientID}}); status != http.StatusBadRequest {
		t.Errorf("expired refresh token: status=%d, want 400", status)
	}
}
