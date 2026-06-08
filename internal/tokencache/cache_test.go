package tokencache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/drogers0/awsup/internal/auth"
)

// minimalJWT builds a three-part JWT with the given header and payload maps
// (no real signature needed — ParseTokenClaims doesn't verify).
func minimalJWT(header, payload map[string]any) string {
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hBytes)
	p := base64.RawURLEncoding.EncodeToString(pBytes)
	return h + "." + p + ".sig"
}

func TestLoad_Missing(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatalf("expected nil cache, got %+v", c)
	}
}

func TestLoad_Corrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON, got nil")
	}
}

func TestGetValid_FreshCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")

	// Build a fresh cache with an ID token that expires far in the future.
	jwt := minimalJWT(
		map[string]any{"alg": "HS256"},
		map[string]any{
			"aud":              "test-client",
			"exp":              float64(9999999999),
			"userId":           "u1",
			"groupIds":         "g1,",
			"email":            "x@y.com",
			"cognito:username": "idc_x@y.com",
		},
	)
	c := &Cache{
		IDToken:     jwt,
		AccessToken: "access-token", // required for fast path (avoids realtime auth break)
		ExpiresAt:   time.Now().Add(2 * time.Hour),
		AppClientID: "test-client",
		UserPoolID:  "us-east-1_test",
		UserID:      "u1",
		Email:       "x@y.com",
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}

	// GetValid should return the cached value without making any HTTP calls.
	got, err := GetValid(path, "test-client", "us-east-1_test", "http://should-not-be-called")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil cache")
	}
	if got.UserID != "u1" {
		t.Errorf("UserID: got %q, want %q", got.UserID, "u1")
	}
	if got.Email != "x@y.com" {
		t.Errorf("Email: got %q, want %q", got.Email, "x@y.com")
	}
}

func TestGetValid_ExpiredIDToken_ValidRefresh(t *testing.T) {
	// Build a refreshed JWT with a known exp; ExpiresAt must derive from it.
	knownExp := time.Now().Add(2 * time.Hour).Unix()
	jwt := minimalJWT(
		map[string]any{"alg": "HS256"},
		map[string]any{
			"aud":              "test-client",
			"exp":              float64(knownExp),
			"userId":           "u1",
			"groupIds":         "g1,",
			"email":            "x@y.com",
			"cognito:username": "idc_x@y.com",
		},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		// InitiateAuth response shape. Refresh derives expiry from the JWT exp.
		json.NewEncoder(w).Encode(map[string]any{
			"AuthenticationResult": map[string]any{
				"IdToken":     jwt,
				"AccessToken": "access-token-value",
			},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")

	expired := &Cache{
		IDToken:      "hdr.e30.sig",
		RefreshToken: "refresh-tok",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		AppClientID:  "test-client",
		UserPoolID:   "us-east-1_test",
	}
	if err := Save(path, expired); err != nil {
		t.Fatal(err)
	}

	got, err := GetValid(path, "test-client", "us-east-1_test", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil cache")
	}
	if got.UserID != "u1" {
		t.Errorf("UserID: got %q, want %q", got.UserID, "u1")
	}
	if got.Email != "x@y.com" {
		t.Errorf("Email: got %q, want %q", got.Email, "x@y.com")
	}
	if got.RefreshToken != "refresh-tok" {
		t.Errorf("RefreshToken should be preserved: got %q", got.RefreshToken)
	}
	if got.ExpiresAt.Unix() != knownExp {
		t.Errorf("ExpiresAt = %d, want %d (from JWT exp)", got.ExpiresAt.Unix(), knownExp)
	}
}

func TestGetValid_RefreshRejected_NoBrowser(t *testing.T) {
	// Server rejects the refresh token (as Cognito does for an expired one).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"__type": "NotAuthorizedException"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")

	expired := &Cache{
		IDToken:      "hdr.e30.sig",
		RefreshToken: "dead-refresh-tok",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		AppClientID:  "test-client",
		UserPoolID:   "us-east-1_test",
	}
	if err := Save(path, expired); err != nil {
		t.Fatal(err)
	}

	// Refresh fails and there is no browser session in the test env. The error
	// should be the honest ErrSessionExpired, not ErrNoSession.
	_, err := GetValid(path, "test-client", "us-east-1_test", srv.URL)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestGetValid_ProfileMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")

	// Save a cache with a different AppClientID.
	c := &Cache{
		IDToken:     "hdr.e30.sig",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
		AppClientID: "other-client",
		UserPoolID:  "us-east-1_test",
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}

	// GetValid with a different appClientID — cache should be discarded, then
	// fall back to auth.FromBrowser which returns ErrNoSession in tests.
	_, err := GetValid(path, "test-client", "us-east-1_test", "http://unused")
	if err == nil {
		t.Fatal("expected an error (no browser in test env), got nil")
	}
	if !errors.Is(err, auth.ErrNoSession) {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}
