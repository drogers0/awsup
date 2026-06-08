package tokencache

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	AccessToken  string    `json:"accessToken,omitempty"`
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

// initiateAuthRequest is the InitiateAuth REFRESH_TOKEN_AUTH request body.
type initiateAuthRequest struct {
	AuthFlow       string            `json:"AuthFlow"`
	ClientID       string            `json:"ClientId"`
	AuthParameters map[string]string `json:"AuthParameters"`
}

// initiateAuthResponse is the subset of the InitiateAuth response we consume.
// Cognito does not return a new refresh token here (the existing one is reused).
type initiateAuthResponse struct {
	AuthenticationResult struct {
		IDToken     string `json:"IdToken"`
		AccessToken string `json:"AccessToken"`
	} `json:"AuthenticationResult"`
}

// idpEndpointFor returns the Cognito Identity Provider base URL for a user pool
// ID of the form "<region>_<id>", e.g. "https://cognito-idp.us-east-1.amazonaws.com/".
func idpEndpointFor(userPoolID string) string {
	region, _, _ := strings.Cut(userPoolID, "_")
	return "https://cognito-idp." + region + ".amazonaws.com/"
}

// Refresh obtains new ID and access tokens from c.RefreshToken via the Cognito
// Identity Provider InitiateAuth API (REFRESH_TOKEN_AUTH flow) — the same
// mechanism the TEAM web app uses. This works for IAM Identity Center-federated
// sessions, which the Hosted UI /oauth2/token endpoint rejects with
// invalid_grant. endpoint is the cognito-idp base URL; when empty it is derived
// from c.UserPoolID. In tests, pass an httptest.Server URL. Returns
// ErrSessionExpired on a non-200 response (e.g. an expired refresh token).
func Refresh(c *Cache, endpoint string) (*Cache, error) {
	if endpoint == "" {
		endpoint = idpEndpointFor(c.UserPoolID)
	}

	reqBody, err := json.Marshal(initiateAuthRequest{
		AuthFlow:       "REFRESH_TOKEN_AUTH",
		ClientID:       c.AppClientID,
		AuthParameters: map[string]string{"REFRESH_TOKEN": c.RefreshToken},
	})
	if err != nil {
		return nil, fmt.Errorf("encoding InitiateAuth request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("building InitiateAuth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.InitiateAuth")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("InitiateAuth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrSessionExpired
	}

	var ir initiateAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, fmt.Errorf("decoding InitiateAuth response: %w", err)
	}
	if ir.AuthenticationResult.IDToken == "" {
		return nil, ErrSessionExpired
	}

	tokens, err := auth.ParseTokenClaims(ir.AuthenticationResult.IDToken, c.AppClientID)
	if err != nil {
		return nil, fmt.Errorf("parsing refreshed IdToken: %w", err)
	}

	newCache := &Cache{
		IDToken:      ir.AuthenticationResult.IDToken,
		AccessToken:  ir.AuthenticationResult.AccessToken,
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
//  3. Tries to refresh via InitiateAuth if a refresh token is present.
//  4. Falls back to auth.FromBrowser.
//
// idpEndpoint is the cognito-idp base URL passed through to Refresh; when empty
// it is derived from userPoolID. Tests pass an httptest.Server URL.
func GetValid(cachePath, appClientID, userPoolID, idpEndpoint string) (*Cache, error) {
	c, err := Load(cachePath)
	if err != nil {
		return nil, err
	}

	// Discard on profile mismatch.
	if c != nil && (c.AppClientID != appClientID || c.UserPoolID != userPoolID) {
		c = nil
	}

	if c != nil && c.AccessToken != "" && time.Until(c.ExpiresAt) > 60*time.Second {
		return c, nil
	}

	var refreshErr error
	if c != nil && c.RefreshToken != "" {
		refreshed, err := Refresh(c, idpEndpoint)
		if err == nil {
			if saveErr := Save(cachePath, refreshed); saveErr != nil {
				return nil, saveErr
			}
			return refreshed, nil
		}
		// Remember why refresh failed; fall through to browser extraction.
		refreshErr = err
	}

	// Fall back to browser extraction.
	tokens, err := auth.FromBrowser(appClientID)
	if err != nil {
		// If we had a refresh token that the server rejected, the session has
		// genuinely expired — that is more accurate than "no browser session".
		if refreshErr != nil && errors.Is(err, auth.ErrNoSession) {
			return nil, refreshErr
		}
		return nil, err
	}
	fresh := &Cache{
		IDToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
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
