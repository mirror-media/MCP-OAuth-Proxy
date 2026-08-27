package models

import (
	"time"
)

type User struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	FullName      string    `json:"full_name"`
	PasswordHash  string    `json:"-"`
	IsAdmin       bool      `json:"is_admin"`
	EmailVerified bool      `json:"email_verified"`
	AvatarURL     string    `json:"avatar_url"`
	Provider      string    `json:"provider"` // "local", "google"
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Client struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	IsTrusted    bool      `json:"is_trusted"`
	CreatedAt    time.Time `json:"created_at"`
}

type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Nonce               string    `json:"nonce"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
}

type RSAKey struct {
	ID         string    `json:"id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	CreatedAt  time.Time `json:"created_at"`
}
