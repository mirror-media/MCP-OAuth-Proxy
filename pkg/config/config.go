package config

import (
	"os"
	"strings"
)

type Config struct {
	Port               string
	ExternalDomain     string
	Issuer             string
	DBHost             string
	DBPort             string
	DBUser             string
	DBPassword         string
	DBName             string
	DBSSLMode          string
	GoogleClientID     string
	GoogleClientSecret string
	AllowedDomains     []string
	AdminUsername      string
	AdminPassword      string
}

func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	externalDomain := os.Getenv("EXTERNAL_DOMAIN")
	if externalDomain == "" {
		externalDomain = os.Getenv("ZITADEL_EXTERNALDOMAIN")
	}
	if externalDomain == "" {
		externalDomain = "mcp-oauth-proxy-983956931553.asia-east1.run.app"
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		if strings.HasPrefix(externalDomain, "http://") || strings.HasPrefix(externalDomain, "https://") {
			issuer = externalDomain
		} else {
			issuer = "https://" + externalDomain
		}
	}

	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = os.Getenv("ZITADEL_DATABASE_POSTGRES_HOST")
	}
	if dbHost == "" {
		dbHost = "localhost"
	}

	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = os.Getenv("ZITADEL_DATABASE_POSTGRES_PORT")
	}
	if dbPort == "" {
		dbPort = "5432"
	}

	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = os.Getenv("ZITADEL_DATABASE_POSTGRES_USER_USERNAME")
	}
	if dbUser == "" {
		dbUser = "zitadel"
	}

	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		dbPassword = os.Getenv("ZITADEL_DATABASE_POSTGRES_USER_PASSWORD")
	}
	if dbPassword == "" {
		dbPassword = "ZitadelDbPassword123!"
	}

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "oauth_proxy"
	}

	dbSSLMode := os.Getenv("DB_SSL_MODE")
	if dbSSLMode == "" {
		dbSSLMode = os.Getenv("ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE")
	}
	if dbSSLMode == "" {
		dbSSLMode = "disable"
	}

	allowedDomainsRaw := os.Getenv("ALLOWED_EMAIL_DOMAINS")
	var allowedDomains []string
	if allowedDomainsRaw != "" {
		for _, d := range strings.Split(allowedDomainsRaw, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				allowedDomains = append(allowedDomains, strings.ToLower(d))
			}
		}
	}

	adminUser := os.Getenv("ADMIN_USERNAME")
	if adminUser == "" {
		adminUser = "admin"
	}

	adminPass := os.Getenv("ADMIN_PASSWORD")
	if adminPass == "" {
		adminPass = "ZitadelAdmin123!"
	}

	return &Config{
		Port:               port,
		ExternalDomain:     externalDomain,
		Issuer:             issuer,
		DBHost:             dbHost,
		DBPort:             dbPort,
		DBUser:             dbUser,
		DBPassword:         dbPassword,
		DBName:             dbName,
		DBSSLMode:          dbSSLMode,
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		AllowedDomains:     allowedDomains,
		AdminUsername:      adminUser,
		AdminPassword:      adminPass,
	}
}
