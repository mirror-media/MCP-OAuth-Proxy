package config

import (
	"os"
	"strconv"
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
	// TrustedProxyHops is the number of X-Forwarded-For entries, counted from
	// the right, that the infrastructure in front of the service appends. The
	// client IP is the leftmost of those entries; entries before it are set by
	// the caller. 0 ignores X-Forwarded-For and uses the connection address.
	TrustedProxyHops int
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

	// Cloud Run (run.app URL or domain mapping) appends one entry. An external
	// Application Load Balancer appends two: client IP, load balancer IP.
	trustedProxyHops := 1
	if v := os.Getenv("TRUSTED_PROXY_HOPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			trustedProxyHops = n
		}
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
		TrustedProxyHops:   trustedProxyHops,
	}
}
