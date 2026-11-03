package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/db"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
)

type JWTManager struct {
	keyID      string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	mu         sync.RWMutex
}

func InitJWTManager(store *db.Store) (*JWTManager, error) {
	key, err := store.GetRSAKey()
	if err == nil && key != nil {
		priv, pub, err := parsePEMKeys(key.PrivateKey, key.PublicKey)
		if err == nil {
			return &JWTManager{
				keyID:      key.ID,
				privateKey: priv,
				publicKey:  pub,
			}, nil
		}
		log.Printf("Warning parsing DB RSA keys: %v, generating new keypair...", err)
	}

	// Generate new 2048-bit RSA Keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	keyID := uuid.New().String()
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	_ = store.SaveRSAKey(&models.RSAKey{
		ID:         keyID,
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
	})

	return &JWTManager{
		keyID:      keyID,
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
	}, nil
}

func parsePEMKeys(privPEM, pubPEM string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}

	pubBlock, _ := pem.Decode([]byte(pubPEM))
	if pubBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode public key PEM")
	}
	pubKeyAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	pubKey, ok := pubKeyAny.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an RSA public key")
	}

	return privKey, pubKey, nil
}

func (j *JWTManager) GetJWKS() map[string]interface{} {
	j.mu.RLock()
	defer j.mu.RUnlock()

	nBase64 := base64.RawURLEncoding.EncodeToString(j.publicKey.N.Bytes())
	eBytes := big.NewInt(int64(j.publicKey.E)).Bytes()
	eBase64 := base64.RawURLEncoding.EncodeToString(eBytes)

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": j.keyID,
				"n":   nBase64,
				"e":   eBase64,
			},
		},
	}
}

func (j *JWTManager) GenerateTokens(issuer string, user *models.User, clientID, scope, nonce string) (accessToken string, idToken string, expiresIn int, err error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	expiresIn = 3600 // 1 hour
	accessExpiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	// Mint Access Token (RS256)
	accessClaims := jwt.MapClaims{
		"iss":                issuer,
		"sub":                user.ID,
		"aud":                []string{clientID, issuer},
		"exp":                accessExpiresAt.Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"jti":                uuid.New().String(),
		"client_id":          clientID,
		"scope":              scope,
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
		"name":               user.FullName,
		"preferred_username": user.Username,
	}

	accessJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessJWT.Header["kid"] = j.keyID
	accessToken, err = accessJWT.SignedString(j.privateKey)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Mint ID Token (RS256)
	idClaims := jwt.MapClaims{
		"iss":                issuer,
		"sub":                user.ID,
		"aud":                clientID,
		"exp":                accessExpiresAt.Unix(),
		"iat":                now.Unix(),
		"auth_time":          now.Unix(),
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
		"name":               user.FullName,
		"preferred_username": user.Username,
		"picture":            user.AvatarURL,
	}

	if nonce != "" {
		idClaims["nonce"] = nonce
	}

	idJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	idJWT.Header["kid"] = j.keyID
	idToken, err = idJWT.SignedString(j.privateKey)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to sign id token: %w", err)
	}

	return accessToken, idToken, expiresIn, nil
}

// VerifyToken verifies an RSA-signed JWT token string using the active RSA public key.
// It strictly validates:
// 1. Algorithm is explicitly RS256 (rejecting 'none', HMAC, or unexpected algorithms).
// 2. RSA cryptographic signature using the public key.
// 3. Expiration time (exp) is present and not expired.
// 4. Not-before time (nbf) if present.
func (j *JWTManager) VerifyToken(tokenStr string) (jwt.MapClaims, error) {
	if j == nil {
		return nil, fmt.Errorf("jwt manager is not initialized")
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	if j.publicKey == nil {
		return nil, fmt.Errorf("rsa public key is not initialized")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// Strict check: algorithm MUST be RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Header["alg"])
		}
		if kid, ok := token.Header["kid"].(string); ok && kid != "" && kid != j.keyID {
			return nil, fmt.Errorf("unknown key ID (kid): %s", kid)
		}
		return j.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// TokenFingerprint returns a truncated SHA-256 fingerprint of the token for audit logging.
func TokenFingerprint(tokenStr string) string {
	if tokenStr == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(tokenStr))
	return fmt.Sprintf("%x", hash[:8])
}

// ExtractTokenMetadataForLog extracts non-sensitive identifiers (jti, fingerprint) for tracing without leaking secrets.
func ExtractTokenMetadataForLog(tokenStr string) (jti string, fingerprint string) {
	fingerprint = TokenFingerprint(tokenStr)
	token, _, _ := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if token != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if id, ok := claims["jti"].(string); ok {
				jti = id
			}
		}
	}
	return jti, fingerprint
}

// RotateKey generates a new RSA keypair, persists it to DB, and activates it in the JWTManager.
func (j *JWTManager) RotateKey(store *db.Store) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	keyID := uuid.New().String()
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	err = store.SaveRSAKey(&models.RSAKey{
		ID:         keyID,
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
	})
	if err != nil {
		return fmt.Errorf("failed to save rotated RSA key to DB: %w", err)
	}

	j.mu.Lock()
	j.keyID = keyID
	j.privateKey = privKey
	j.publicKey = &privKey.PublicKey
	j.mu.Unlock()

	log.Printf("Successfully rotated RSA Keypair. New Key ID: %s", keyID)
	return nil
}

func VerifyPKCE(codeVerifier, codeChallenge, method string) bool {
	if codeChallenge == "" {
		return true // PKCE optional for confidential clients
	}
	if strings.ToUpper(method) == "S256" {
		h := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == codeChallenge
	}
	// Plain method
	return codeVerifier == codeChallenge
}
