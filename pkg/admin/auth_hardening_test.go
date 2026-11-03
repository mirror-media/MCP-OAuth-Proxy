package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/crypto"
)

func createTestCryptoManager(t *testing.T) *crypto.JWTManager {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	// We can generate tokens and verify with this manager
	// Note: We use reflect or helper if needed, but GenerateTokens uses internal fields
	// Let's create an unexported/exported test helper or mock if needed
	_ = privKey
	return nil
}

func TestGetSessionUser_DeniesForgedToken(t *testing.T) {
	// Attacker crafts a token with alg: none
	claims := jwt.MapClaims{
		"sub":   "usr_admin_001",
		"email": "admin@mirrormedia.mg",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	forgedToken, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	server := &AdminServer{
		cfg: &config.Config{Issuer: "https://sso.example.test"},
		// jwtManager is nil or unconfigured
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken)

	user := server.GetSessionUser(req)
	if user != nil {
		t.Fatalf("security violation: GetSessionUser MUST NOT accept forged token when jwtManager is nil")
	}
}

func TestRequireAdmin_BlocksNonAdminScopeBearerToken(t *testing.T) {
	server := &AdminServer{
		cfg: &config.Config{Issuer: "https://sso.example.test"},
	}

	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer invalid.forged.token")
	rec := httptest.NewRecorder()

	server.RequireAdmin(next)(rec, req)

	if nextCalled {
		t.Fatal("security violation: RequireAdmin allowed execution without valid authentication")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}
}
