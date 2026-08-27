package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	db *sql.DB
}

func Init(cfg *config.Config) (*Store, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrateSchema(); err != nil {
		return nil, fmt.Errorf("failed schema migration: %w", err)
	}

	if err := s.seedAdmin(cfg); err != nil {
		log.Printf("Warning seeding admin: %v", err)
	}

	return s, nil
}

func (s *Store) migrateSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(64) PRIMARY KEY,
			username VARCHAR(128) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			full_name VARCHAR(255),
			password_hash VARCHAR(255),
			is_admin BOOLEAN DEFAULT FALSE,
			email_verified BOOLEAN DEFAULT TRUE,
			avatar_url TEXT DEFAULT '',
			provider VARCHAR(32) DEFAULT 'local',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS clients (
			id VARCHAR(64) PRIMARY KEY,
			secret VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			redirect_uris TEXT NOT NULL,
			is_trusted BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS auth_codes (
			code VARCHAR(128) PRIMARY KEY,
			client_id VARCHAR(64) NOT NULL,
			user_id VARCHAR(64) NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT,
			code_challenge TEXT,
			code_challenge_method VARCHAR(16),
			nonce TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			token VARCHAR(128) PRIMARY KEY,
			client_id VARCHAR(64) NOT NULL,
			user_id VARCHAR(64) NOT NULL,
			scope TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS rsa_keys (
			id VARCHAR(64) PRIMARY KEY,
			private_key TEXT NOT NULL,
			public_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) seedAdmin(cfg *config.Config) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	adminID := "usr_admin_001"
	email := "admin@mirrormedia.mg"
	now := time.Now()

	// Seed or update admin user
	_, err = s.db.Exec(`INSERT INTO users (id, username, email, full_name, password_hash, is_admin, email_verified, avatar_url, provider, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, true, true, '', 'local', $6, $7)
		ON CONFLICT (username) DO UPDATE SET password_hash = $5, is_admin = true;`,
		adminID, cfg.AdminUsername, email, "System Administrator", string(hash), now, now)

	// Seed default Console client ID with sso.mirrormedia.mg URIs
	redirectURIs := fmt.Sprintf("https://sso.mirrormedia.mg/ui/console/,https://sso.mirrormedia.mg/ui/console,%s/ui/console/,%s/ui/console,%s/ui/console/auth/callback", cfg.Issuer, cfg.Issuer, cfg.Issuer)
	_, _ = s.db.Exec(`INSERT INTO clients (id, secret, name, redirect_uris, is_trusted, created_at)
		VALUES ($1, $2, $3, $4, true, $5)
		ON CONFLICT (id) DO UPDATE SET redirect_uris = $4;`,
		"387661340942270110", "zitadel-client-secret-123", "Management Console", redirectURIs, now)

	// Seed default GA & Mirror Media CMS MCP client
	gaMCPURIs := "https://claude.ai/oauth/callback,https://desktop.claude.ai/oauth/callback,http://localhost,http://127.0.0.1,https://ga-mcp-983956931553.asia-east1.run.app/sse,https://sso.mirrormedia.mg/mcp/sse,https://sso.mirrormedia.mg/mcp/,https://sso.mirrormedia.mg/daily/sse,https://sso.mirrormedia.mg/daily/,*"
	_, _ = s.db.Exec(`INSERT INTO clients (id, secret, name, redirect_uris, is_trusted, created_at)
		VALUES ($1, $2, $3, $4, true, $5)
		ON CONFLICT (id) DO UPDATE SET redirect_uris = $4;`,
		"ga-mcp-client-001", "ga-mcp-secret-123", "Google Analytics & Mirror Media CMS MCP", gaMCPURIs, now)

	return err
}

func (s *Store) GetUserByUsernameOrEmail(identifier string) (*models.User, error) {
	u := &models.User{}
	identifierLower := strings.ToLower(strings.TrimSpace(identifier))
	query := `SELECT id, username, email, COALESCE(full_name, ''), password_hash, is_admin, email_verified, COALESCE(avatar_url, ''), provider, created_at, updated_at
		FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1;`

	err := s.db.QueryRow(query, identifierLower).Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.PasswordHash,
		&u.IsAdmin, &u.EmailVerified, &u.AvatarURL, &u.Provider, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUserByID(id string) (*models.User, error) {
	u := &models.User{}
	query := `SELECT id, username, email, COALESCE(full_name, ''), password_hash, is_admin, email_verified, COALESCE(avatar_url, ''), provider, created_at, updated_at
		FROM users WHERE id = $1;`

	err := s.db.QueryRow(query, id).Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.PasswordHash,
		&u.IsAdmin, &u.EmailVerified, &u.AvatarURL, &u.Provider, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) CreateOrUpdateGoogleUser(email, name, avatarURL string) (*models.User, error) {
	existing, err := s.GetUserByUsernameOrEmail(email)
	now := time.Now()

	// Check if user should be admin based on email
	emailLower := strings.ToLower(strings.TrimSpace(email))
	isAdmin := strings.HasPrefix(emailLower, "admin@") || strings.HasPrefix(emailLower, "hcchien@") || os.Getenv("ADMIN_EMAIL") == emailLower

	if err == nil {
		// Update avatar, full name, and admin status if applicable
		if isAdmin && !existing.IsAdmin {
			_, _ = s.db.Exec(`UPDATE users SET is_admin = true, full_name = $1, avatar_url = $2, updated_at = $3 WHERE id = $4;`,
				name, avatarURL, now, existing.ID)
			existing.IsAdmin = true
		} else {
			_, _ = s.db.Exec(`UPDATE users SET full_name = $1, avatar_url = $2, updated_at = $3 WHERE id = $4;`,
				name, avatarURL, now, existing.ID)
		}
		existing.FullName = name
		existing.AvatarURL = avatarURL
		return existing, nil
	}

	// Create new user
	username := strings.Split(email, "@")[0]
	userID := fmt.Sprintf("usr_gws_%d", time.Now().UnixNano())

	_, err = s.db.Exec(`INSERT INTO users (id, username, email, full_name, password_hash, is_admin, email_verified, avatar_url, provider, created_at, updated_at)
		VALUES ($1, $2, $3, $4, '', $5, true, $6, 'google', $7, $8);`,
		userID, username, email, name, isAdmin, avatarURL, now, now)
	if err != nil {
		return nil, err
	}

	return s.GetUserByID(userID)
}

func (s *Store) CreateUser(u *models.User) error {
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	_, err := s.db.Exec(`INSERT INTO users (id, username, email, full_name, password_hash, is_admin, email_verified, avatar_url, provider, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);`,
		u.ID, u.Username, u.Email, u.FullName, u.PasswordHash, u.IsAdmin, u.EmailVerified, u.AvatarURL, u.Provider, u.CreatedAt, u.UpdatedAt)
	return err
}

func (s *Store) ListUsers() ([]*models.User, error) {
	rows, err := s.db.Query(`SELECT id, username, email, COALESCE(full_name, ''), is_admin, email_verified, COALESCE(avatar_url, ''), provider, created_at, updated_at FROM users ORDER BY created_at DESC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.IsAdmin, &u.EmailVerified, &u.AvatarURL, &u.Provider, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) DeleteUser(id string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = $1;`, id)
	return err
}

func (s *Store) GetClient(id string) (*models.Client, error) {
	c := &models.Client{}
	var urisStr string
	query := `SELECT id, secret, name, redirect_uris, is_trusted, created_at FROM clients WHERE id = $1;`

	err := s.db.QueryRow(query, id).Scan(&c.ID, &c.Secret, &c.Name, &urisStr, &c.IsTrusted, &c.CreatedAt)
	if err != nil {
		return nil, err
	}

	if urisStr != "" {
		c.RedirectURIs = strings.Split(urisStr, ",")
	}
	return c, nil
}

func (s *Store) CreateClient(c *models.Client) error {
	c.CreatedAt = time.Now()
	urisStr := strings.Join(c.RedirectURIs, ",")
	_, err := s.db.Exec(`INSERT INTO clients (id, secret, name, redirect_uris, is_trusted, created_at)
		VALUES ($1, $2, $3, $4, $5, $6);`,
		c.ID, c.Secret, c.Name, urisStr, c.IsTrusted, c.CreatedAt)
	return err
}

func (s *Store) ListClients() ([]*models.Client, error) {
	rows, err := s.db.Query(`SELECT id, secret, name, redirect_uris, is_trusted, created_at FROM clients ORDER BY created_at DESC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*models.Client
	for rows.Next() {
		c := &models.Client{}
		var urisStr string
		if err := rows.Scan(&c.ID, &c.Secret, &c.Name, &urisStr, &c.IsTrusted, &c.CreatedAt); err != nil {
			return nil, err
		}
		if urisStr != "" {
			c.RedirectURIs = strings.Split(urisStr, ",")
		}
		clients = append(clients, c)
	}
	return clients, nil
}

func (s *Store) DeleteClient(id string) error {
	_, err := s.db.Exec(`DELETE FROM clients WHERE id = $1;`, id)
	return err
}

func (s *Store) SaveAuthCode(ac *models.AuthCode) error {
	_, err := s.db.Exec(`INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);`,
		ac.Code, ac.ClientID, ac.UserID, ac.RedirectURI, ac.Scope, ac.CodeChallenge, ac.CodeChallengeMethod, ac.Nonce, ac.ExpiresAt)
	return err
}

func (s *Store) GetAndConsumeAuthCode(code string) (*models.AuthCode, error) {
	ac := &models.AuthCode{}
	query := `SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at
		FROM auth_codes WHERE code = $1;`

	err := s.db.QueryRow(query, code).Scan(
		&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI, &ac.Scope,
		&ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Nonce, &ac.ExpiresAt)
	if err != nil {
		return nil, err
	}

	// Delete used code
	_, _ = s.db.Exec(`DELETE FROM auth_codes WHERE code = $1;`, code)
	return ac, nil
}

func (s *Store) SaveRefreshToken(rt *models.RefreshToken) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5);`,
		rt.Token, rt.ClientID, rt.UserID, rt.Scope, rt.ExpiresAt)
	return err
}

func (s *Store) GetRSAKey() (*models.RSAKey, error) {
	k := &models.RSAKey{}
	err := s.db.QueryRow(`SELECT id, private_key, public_key, created_at FROM rsa_keys ORDER BY created_at DESC LIMIT 1;`).
		Scan(&k.ID, &k.PrivateKey, &k.PublicKey, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Store) SaveRSAKey(k *models.RSAKey) error {
	k.CreatedAt = time.Now()
	_, err := s.db.Exec(`INSERT INTO rsa_keys (id, private_key, public_key, created_at) VALUES ($1, $2, $3, $4);`,
		k.ID, k.PrivateKey, k.PublicKey, k.CreatedAt)
	return err
}
