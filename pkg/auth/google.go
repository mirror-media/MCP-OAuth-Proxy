package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/db"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleHandler struct {
	cfg   *config.Config
	store *db.Store
}

func NewGoogleHandler(cfg *config.Config, store *db.Store) *GoogleHandler {
	return &GoogleHandler{
		cfg:   cfg,
		store: store,
	}
}

func (gh *GoogleHandler) getOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     gh.cfg.GoogleClientID,
		ClientSecret: gh.cfg.GoogleClientSecret,
		RedirectURL:  fmt.Sprintf("%s/auth/google/callback", gh.cfg.Issuer),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"openid",
		},
		Endpoint: google.Endpoint,
	}
}

func (gh *GoogleHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if gh.cfg.GoogleClientID == "" || gh.cfg.GoogleClientSecret == "" {
		http.Error(w, "Google SSO is not configured on this server (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET missing).", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		state = "default"
	}

	oauthConfig := gh.getOAuth2Config()
	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, url, http.StatusFound)
}

type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Domain        string `json:"hd"`
}

func (gh *GoogleHandler) HandleCallback(w http.ResponseWriter, r *http.Request, onSuccess func(w http.ResponseWriter, r *http.Request, user *models.User, state string)) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing authorization code from Google.", http.StatusBadRequest)
		return
	}

	oauthConfig := gh.getOAuth2Config()
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token with Google: %v", err), http.StatusInternalServerError)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch userinfo from Google: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var gUser GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&gUser); err != nil {
		http.Error(w, "Failed to decode Google user info", http.StatusInternalServerError)
		return
	}

	if !gUser.EmailVerified {
		http.Error(w, "Google email is not verified.", http.StatusForbidden)
		return
	}

	// Verify allowed email domains if configured
	emailParts := strings.Split(gUser.Email, "@")
	if len(emailParts) != 2 {
		http.Error(w, "Invalid email format from Google.", http.StatusBadRequest)
		return
	}
	emailDomain := strings.ToLower(emailParts[1])

	if len(gh.cfg.AllowedDomains) > 0 {
		allowed := false
		for _, d := range gh.cfg.AllowedDomains {
			if strings.EqualFold(d, emailDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, fmt.Sprintf("Domain @%s is not permitted to log into this OAuth proxy. Permitted domains: %s", emailDomain, strings.Join(gh.cfg.AllowedDomains, ", ")), http.StatusForbidden)
			return
		}
	}

	// Save/update user in DB
	user, err := gh.store.CreateOrUpdateGoogleUser(gUser.Email, gUser.Name, gUser.Picture)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create/update user in database: %v", err), http.StatusInternalServerError)
		return
	}

	onSuccess(w, r, user, state)
}
