package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/config"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/db"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/models"
	"github.com/mirror-media/mcp-oauth-proxy/pkg/web"
	"golang.org/x/crypto/bcrypt"
)

type AdminServer struct {
	cfg   *config.Config
	store *db.Store
}

func NewAdminServer(cfg *config.Config, store *db.Store) *AdminServer {
	return &AdminServer{cfg: cfg, store: store}
}

func (a *AdminServer) SetSessionCookie(w http.ResponseWriter, user *models.User) {
	sig := a.signSession(user.ID, user.IsAdmin)
	val := fmt.Sprintf("%s:%t:%s", user.ID, user.IsAdmin, sig)

	http.SetCookie(w, &http.Cookie{
		Name:     "mcp_admin_session",
		Value:    val,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *AdminServer) signSession(userID string, isAdmin bool) string {
	h := hmac.New(sha256.New, []byte(a.cfg.AdminPassword))
	h.Write([]byte(fmt.Sprintf("%s:%t", userID, isAdmin)))
	return hex.EncodeToString(h.Sum(nil))
}

func (a *AdminServer) GetSessionUser(r *http.Request) *models.User {
	// Check Bearer Token (JWT Access Token passed by OAuth clients like Claude)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
		if err == nil {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if userID, ok := claims["sub"].(string); ok && userID != "" {
					if u, err := a.store.GetUserByID(userID); err == nil && u != nil {
						return u
					}
				}
				if email, ok := claims["email"].(string); ok && email != "" {
					if u, err := a.store.GetUserByUsernameOrEmail(email); err == nil && u != nil {
						return u
					}
				}
			}
		}
	}

	// Check Basic Auth
	if user, pass, ok := r.BasicAuth(); ok {
		if user == a.cfg.AdminUsername && pass == a.cfg.AdminPassword {
			return &models.User{
				ID:            "usr_admin_001",
				Username:      a.cfg.AdminUsername,
				Email:         "admin@mirrormedia.mg",
				FullName:      "System Administrator",
				IsAdmin:       true,
				EmailVerified: true,
				Provider:      "local",
			}
		}
		u, err := a.store.GetUserByUsernameOrEmail(user)
		if err == nil && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pass)) == nil {
			return u
		}
	}

	// Check Session Cookie
	cookie, err := r.Cookie("mcp_admin_session")
	if err != nil || cookie.Value == "" {
		return nil
	}

	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return nil
	}

	userID, isAdminStr, sig := parts[0], parts[1], parts[2]
	isAdmin := isAdminStr == "true"

	expectedSig := a.signSession(userID, isAdmin)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil
	}

	u, err := a.store.GetUserByID(userID)
	if err != nil {
		return &models.User{
			ID:            userID,
			Username:      "user",
			Email:         "",
			IsAdmin:       isAdmin,
			EmailVerified: true,
			Provider:      "session",
		}
	}
	return u
}

func (a *AdminServer) IsAuthenticated(r *http.Request) bool {
	return a.GetSessionUser(r) != nil
}

func (a *AdminServer) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.IsAuthenticated(r) {
			if strings.HasPrefix(r.URL.Path, "/api/v1/") || strings.HasPrefix(r.URL.Path, "/mcp") || strings.HasPrefix(r.URL.Path, "/daily") || strings.HasPrefix(r.URL.Path, "/messages") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="sso.mirrormedia.mg"`)
				http.Error(w, "Unauthorized: Login or Bearer token required", http.StatusUnauthorized)
				return
			}
			// Redirect unauthenticated user to login
			redirectURI := url.QueryEscape(fmt.Sprintf("%s/ui/console/", a.cfg.Issuer))
			authURL := fmt.Sprintf("/oauth/v2/authorize?client_id=387661340942270110&redirect_uri=%s&response_type=code&scope=openid", redirectURI)
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (a *AdminServer) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := a.GetSessionUser(r)
		if user == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Admin API"`)
			http.Error(w, "Unauthorized: Login required", http.StatusUnauthorized)
			return
		}
		if !user.IsAdmin {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "forbidden",
				"message": "Admin privileges required to perform this action",
			})
			return
		}
		next(w, r)
	}
}

func (a *AdminServer) HandleMe(w http.ResponseWriter, r *http.Request) {
	user := a.GetSessionUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         user.ID,
		"username":   user.Username,
		"email":      user.Email,
		"full_name":  user.FullName,
		"is_admin":   user.IsAdmin,
		"provider":   user.Provider,
		"avatar_url": user.AvatarURL,
	})
}

func (a *AdminServer) HandleConsoleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(web.ConsoleHTML))
}

func (a *AdminServer) HandleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		clients, err := a.store.ListClients()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(clients)

	case http.MethodPost:
		var req struct {
			Name         string   `json:"name"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid json body", http.StatusBadRequest)
			return
		}

		client := &models.Client{
			ID:           uuid.New().String(),
			Secret:       fmt.Sprintf("secret_%s", uuid.New().String()),
			Name:         req.Name,
			RedirectURIs: req.RedirectURIs,
			IsTrusted:    true,
		}

		if err := a.store.CreateClient(client); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(client)
	}
}

func (a *AdminServer) HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/v1/clients/"):]
	if id == "" {
		http.Error(w, "Missing client id", http.StatusBadRequest)
		return
	}
	if err := a.store.DeleteClient(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *AdminServer) HandleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		users, err := a.store.ListUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			FullName string `json:"full_name"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid json body", http.StatusBadRequest)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user := &models.User{
			ID:            fmt.Sprintf("usr_%s", uuid.New().String()),
			Username:      req.Username,
			Email:         req.Email,
			FullName:      req.FullName,
			PasswordHash:  string(hash),
			IsAdmin:       false,
			EmailVerified: true,
			Provider:      "local",
		}

		if err := a.store.CreateUser(user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(user)
	}
}

func (a *AdminServer) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/v1/users/"):]
	if id == "" {
		http.Error(w, "Missing user id", http.StatusBadRequest)
		return
	}
	if err := a.store.DeleteUser(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
