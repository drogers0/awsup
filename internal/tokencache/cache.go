package tokencache

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drogers0/awsup/internal/auth"
)

// ErrSessionExpired is returned when the refresh token is rejected by the server.
var ErrSessionExpired = errors.New("session expired — please sign into TEAM in Chrome and try again")

// Cache holds a persisted Cognito session.
type Cache struct {
	IDToken      string    `json:"idToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UserPoolID   string    `json:"userPoolId"`
	AppClientID  string    `json:"appClientId"`
	UserID       string    `json:"userId"`
	GroupIDs     []string  `json:"groupIds"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
}

// Load reads and deserializes the cache from path. Returns nil, nil if the
// file does not exist.
func Load(path string) (*Cache, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading cache: %w", err)
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing cache: %w", err)
	}
	return &c, nil
}

// Save serializes c to path with mode 0600; the parent directory is created
// with mode 0700 if it does not already exist.
func Save(path string, c *Cache) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("serializing cache: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	return nil
}

// refreshResponse is the JSON body returned by the Cognito token endpoint.
type refreshResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

// Refresh obtains a new ID token using c.RefreshToken against the hosted UI
// token endpoint. hostedUIDomain must be a full base URL, e.g.
// "https://auth.example.auth.us-east-1.amazoncognito.com". In tests, pass the
// httptest.Server URL directly. Returns ErrSessionExpired on a non-200
// response.
func Refresh(c *Cache, hostedUIDomain string) (*Cache, error) {
	tokenURL := strings.TrimRight(hostedUIDomain, "/") + "/oauth2/token"

	vals := url.Values{}
	vals.Set("grant_type", "refresh_token")
	vals.Set("client_id", c.AppClientID)
	vals.Set("refresh_token", c.RefreshToken)

	resp, err := http.PostForm(tokenURL, vals)
	if err != nil {
		return nil, fmt.Errorf("token refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrSessionExpired
	}

	var rr refreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	tokens, err := auth.ParseTokenClaims(rr.IDToken, c.AppClientID)
	if err != nil {
		return nil, fmt.Errorf("parsing refreshed id_token: %w", err)
	}

	newCache := &Cache{
		IDToken:      rr.IDToken,
		RefreshToken: c.RefreshToken,
		ExpiresAt:    tokens.Expiry,
		UserPoolID:   c.UserPoolID,
		AppClientID:  c.AppClientID,
		UserID:       tokens.UserID,
		GroupIDs:     tokens.GroupIDs,
		Email:        tokens.Email,
		Username:     tokens.Username,
	}
	return newCache, nil
}

// GetValid returns a valid cache for the given profile parameters. It:
//  1. Loads the cache file; discards it on AppClientID/UserPoolID mismatch.
//  2. Returns the cached value if the ID token has > 60 seconds remaining.
//  3. Tries to refresh if a refresh token is present.
//  4. Falls back to auth.FromBrowser.
func GetValid(cachePath, appClientID, userPoolID, hostedUIDomain string) (*Cache, error) {
	c, err := Load(cachePath)
	if err != nil {
		return nil, err
	}

	// Discard on profile mismatch.
	if c != nil && (c.AppClientID != appClientID || c.UserPoolID != userPoolID) {
		c = nil
	}

	if c != nil && time.Until(c.ExpiresAt) > 60*time.Second {
		return c, nil
	}

	if c != nil && c.RefreshToken != "" {
		refreshed, err := Refresh(c, hostedUIDomain)
		if err == nil {
			if saveErr := Save(cachePath, refreshed); saveErr != nil {
				return nil, saveErr
			}
			return refreshed, nil
		}
		// Fall through to browser on refresh failure.
	}

	// Fall back to browser extraction.
	tokens, err := auth.FromBrowser(appClientID)
	if err != nil {
		return nil, err
	}
	fresh := &Cache{
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.Expiry,
		UserPoolID:   userPoolID,
		AppClientID:  appClientID,
		UserID:       tokens.UserID,
		GroupIDs:     tokens.GroupIDs,
		Email:        tokens.Email,
		Username:     tokens.Username,
	}
	if saveErr := Save(cachePath, fresh); saveErr != nil {
		return nil, saveErr
	}
	return fresh, nil
}
