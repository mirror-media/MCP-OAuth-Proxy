package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
)

func createTestJWTManager(t *testing.T) *JWTManager {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA key: %v", err)
	}
	return &JWTManager{
		keyID:      "test_key_001",
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
	}
}

func TestVerifyToken_ValidToken(t *testing.T) {
	jm := createTestJWTManager(t)
	user := &models.User{
		ID:            "usr_123",
		Username:      "admin",
		Email:         "admin@mirrormedia.mg",
		FullName:      "Admin User",
		IsAdmin:       true,
		EmailVerified: true,
	}

	accessToken, _, _, err := jm.GenerateTokens("https://sso.test", user, "client_abc", "openid", "")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := jm.VerifyToken(accessToken)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}

	if claims["sub"] != "usr_123" {
		t.Errorf("expected sub usr_123, got %v", claims["sub"])
	}
	if claims["email"] != "admin@mirrormedia.mg" {
		t.Errorf("expected email admin@mirrormedia.mg, got %v", claims["email"])
	}
}

func TestVerifyToken_RejectsAlgNone(t *testing.T) {
	jm := createTestJWTManager(t)

	// Attacker crafts unverified token with alg: none
	claims := jwt.MapClaims{
		"sub":   "usr_123",
		"email": "admin@mirrormedia.mg",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenStr, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to craft none token: %v", err)
	}

	_, err = jm.VerifyToken(tokenStr)
	if err == nil {
		t.Fatal("security violation: VerifyToken MUST reject alg: none tokens")
	}
}

func TestVerifyToken_RejectsForgedSignature(t *testing.T) {
	jm := createTestJWTManager(t)

	// Attacker generates their own RSA key
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"sub":   "usr_123",
		"email": "admin@mirrormedia.mg",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = jm.keyID
	forgedToken, err := token.SignedString(attackerKey)
	if err != nil {
		t.Fatalf("failed to sign forged token: %v", err)
	}

	_, err = jm.VerifyToken(forgedToken)
	if err == nil {
		t.Fatal("security violation: VerifyToken MUST reject tokens signed by unauthorized key")
	}
}

func TestVerifyToken_RejectsExpiredToken(t *testing.T) {
	jm := createTestJWTManager(t)

	claims := jwt.MapClaims{
		"sub":   "usr_123",
		"email": "admin@mirrormedia.mg",
		"exp":   time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = jm.keyID
	expiredToken, err := token.SignedString(jm.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = jm.VerifyToken(expiredToken)
	if err == nil {
		t.Fatal("security violation: VerifyToken MUST reject expired tokens")
	}
}

func TestVerifyToken_RejectsMissingExp(t *testing.T) {
	jm := createTestJWTManager(t)

	claims := jwt.MapClaims{
		"sub":   "usr_123",
		"email": "admin@mirrormedia.mg",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = jm.keyID
	noExpToken, err := token.SignedString(jm.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = jm.VerifyToken(noExpToken)
	if err == nil {
		t.Fatal("security violation: VerifyToken MUST reject tokens with missing exp")
	}
}

func TestVerifyToken_RejectsHMACAlgorithmConfusion(t *testing.T) {
	jm := createTestJWTManager(t)

	// Attacker tries HMAC algorithm confusion
	claims := jwt.MapClaims{
		"sub":   "usr_123",
		"email": "admin@mirrormedia.mg",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hmacToken, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to sign HMAC token: %v", err)
	}

	_, err = jm.VerifyToken(hmacToken)
	if err == nil {
		t.Fatal("security violation: VerifyToken MUST reject HMAC algorithm confusion")
	}
}

func TestExtractTokenMetadataForLog(t *testing.T) {
	tokenStr := "some.arbitrary.token"
	jti, fp := ExtractTokenMetadataForLog(tokenStr)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if len(fp) != 16 {
		t.Fatalf("expected 16 hex char fingerprint, got %s", fp)
	}
	if jti != "" {
		t.Fatalf("expected empty jti for non-jwt string, got %s", jti)
	}

	// With proper JWT having JTI
	testJTI := uuid.New().String()
	claims := jwt.MapClaims{
		"jti": testJTI,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	jti, fp = ExtractTokenMetadataForLog(signed)
	if jti != testJTI {
		t.Fatalf("expected jti %s, got %s", testJTI, jti)
	}
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}
