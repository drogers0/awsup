package config_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drogers0/awsup/internal/auth"
	"github.com/drogers0/awsup/internal/config"
)

// makeTestJWT builds a minimal JWT with the given payload (no signature verification).
func makeTestJWT(payload map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	p, _ := json.Marshal(payload)
	return fmt.Sprintf("%s.%s.fakesig", header, base64.RawURLEncoding.EncodeToString(p))
}

// amplifyServer spins up an httptest server that serves a fake index.html
// referencing /static/js/main.abc123.js and a JS bundle with the given content.
func amplifyServer(t *testing.T, bundleContent string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><script defer="defer" src="/static/js/main.abc123.js"></script></head></html>`)
	})
	mux.HandleFunc("/static/js/main.abc123.js", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, bundleContent)
	})
	return httptest.NewServer(mux)
}

func TestFetchAmplifyURLsSuccess(t *testing.T) {
	bundle := `var x="https://abc123def.appsync-api.us-east-1.amazonaws.com/graphql";` +
		`var y="team-prod.auth.us-east-1.amazoncognito.com";`
	srv := amplifyServer(t, bundle)
	defer srv.Close()

	// fetchAmplifyURLs is unexported; test via DiscoverFromSession with a valid token.
	idTok := makeTestJWT(map[string]any{
		"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
		"aud": "test-client",
	})
	s := auth.RawSession{AppClientID: "test-client", FrontendURL: srv.URL, IDToken: idTok}
	cfg, err := config.DiscoverFromSession("default", s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppSyncEndpoint != "https://abc123def.appsync-api.us-east-1.amazonaws.com/graphql" {
		t.Errorf("AppSyncEndpoint = %q", cfg.AppSyncEndpoint)
	}
	if cfg.HostedUIDomain != "https://team-prod.auth.us-east-1.amazoncognito.com" {
		t.Errorf("HostedUIDomain = %q", cfg.HostedUIDomain)
	}
}

func TestFetchAmplifyURLsPartialNoHostedUI(t *testing.T) {
	bundle := `var x="https://abc123def.appsync-api.us-east-1.amazonaws.com/graphql";`
	srv := amplifyServer(t, bundle)
	defer srv.Close()

	idTok := makeTestJWT(map[string]any{
		"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
	})
	s := auth.RawSession{AppClientID: "c", FrontendURL: srv.URL, IDToken: idTok}
	cfg, err := config.DiscoverFromSession("default", s)
	if cfg == nil {
		t.Fatal("expected non-nil Config on partial discovery")
	}
	if cfg.AppSyncEndpoint == "" {
		t.Error("AppSyncEndpoint should be populated")
	}
	if cfg.HostedUIDomain != "" {
		t.Errorf("HostedUIDomain should be empty, got %q", cfg.HostedUIDomain)
	}
	if err == nil {
		t.Error("expected error for missing HostedUIDomain")
	}
	if !strings.Contains(err.Error(), "TEAM_COGNITO_HOSTED_UI_DOMAIN") {
		t.Errorf("error should name the missing field: %v", err)
	}
}

func TestFetchAmplifyURLsPartialNoAppSync(t *testing.T) {
	bundle := `var y="team-prod.auth.us-east-1.amazoncognito.com";`
	srv := amplifyServer(t, bundle)
	defer srv.Close()

	idTok := makeTestJWT(map[string]any{
		"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
	})
	s := auth.RawSession{AppClientID: "c", FrontendURL: srv.URL, IDToken: idTok}
	cfg, err := config.DiscoverFromSession("default", s)
	if cfg == nil {
		t.Fatal("expected non-nil Config on partial discovery")
	}
	if cfg.AppSyncEndpoint != "" {
		t.Errorf("AppSyncEndpoint should be empty, got %q", cfg.AppSyncEndpoint)
	}
	if cfg.HostedUIDomain == "" {
		t.Error("HostedUIDomain should be populated")
	}
	if err == nil {
		t.Error("expected error for missing AppSyncEndpoint")
	}
	if !strings.Contains(err.Error(), "TEAM_APPSYNC_ENDPOINT") {
		t.Errorf("error should name the missing field: %v", err)
	}
}

func TestDiscoverFromSession_PartialFetch_NoBundleRef(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>no bundle here</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	idTok := makeTestJWT(map[string]any{
		"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
		"aud": "client-x",
	})
	s := auth.RawSession{AppClientID: "client-x", FrontendURL: srv.URL, IDToken: idTok}
	cfg, err := config.DiscoverFromSession("default", s)
	if cfg == nil {
		t.Fatal("expected non-nil Config even on fetch failure")
	}
	if err == nil {
		t.Error("expected error when no JS bundle found")
	}
	// Locally-derived fields must survive the network failure.
	if cfg.AppClientID != "client-x" {
		t.Errorf("AppClientID = %q, want client-x", cfg.AppClientID)
	}
	if cfg.UserPoolID != "us-east-1_TestPool" {
		t.Errorf("UserPoolID = %q", cfg.UserPoolID)
	}
	if cfg.FrontendURL != srv.URL {
		t.Errorf("FrontendURL = %q, want %q", cfg.FrontendURL, srv.URL)
	}
	if cfg.AmplifyUserAgent != config.DefaultAmplifyUserAgent {
		t.Errorf("AmplifyUserAgent = %q", cfg.AmplifyUserAgent)
	}
	if cfg.AppSyncEndpoint != "" || cfg.HostedUIDomain != "" {
		t.Errorf("network-derived fields should be empty: appsync=%q hostedUI=%q",
			cfg.AppSyncEndpoint, cfg.HostedUIDomain)
	}
}

func TestDiscoverFromSession_Unreachable(t *testing.T) {
	// Spin up an httptest server then close it immediately to get a guaranteed-closed URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	idTok := makeTestJWT(map[string]any{
		"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
		"aud": "client-x",
	})
	s := auth.RawSession{AppClientID: "client-x", FrontendURL: closedURL, IDToken: idTok}
	cfg, err := config.DiscoverFromSession("default", s)
	if cfg == nil {
		t.Fatal("expected non-nil Config even on fetch failure")
	}
	if err == nil {
		t.Error("expected error for unreachable frontend")
	}
	if cfg.AppSyncEndpoint != "" || cfg.HostedUIDomain != "" {
		t.Errorf("fields should be empty on unreachable fetch: appsync=%q hostedUI=%q",
			cfg.AppSyncEndpoint, cfg.HostedUIDomain)
	}
	// Locally-derived fields populated.
	if cfg.AppClientID != "client-x" || cfg.UserPoolID != "us-east-1_TestPool" {
		t.Errorf("locally-derived fields not preserved: clientID=%q poolID=%q",
			cfg.AppClientID, cfg.UserPoolID)
	}
}

func TestDiscoverFromSession_AllFields(t *testing.T) {
	bundle := `var x="https://abc123def.appsync-api.us-east-1.amazonaws.com/graphql";` +
		`var y="team-prod.auth.us-east-1.amazoncognito.com";`
	srv := amplifyServer(t, bundle)
	defer srv.Close()

	idTok := makeTestJWT(map[string]any{
		"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_MyPool",
		"aud": "my-client",
	})
	s := auth.RawSession{AppClientID: "my-client", FrontendURL: srv.URL, IDToken: idTok}
	cfg, err := config.DiscoverFromSession("staging", s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "staging" {
		t.Errorf("Profile = %q, want staging", cfg.Profile)
	}
	if cfg.AppClientID != "my-client" {
		t.Errorf("AppClientID = %q", cfg.AppClientID)
	}
	if cfg.UserPoolID != "us-east-1_MyPool" {
		t.Errorf("UserPoolID = %q", cfg.UserPoolID)
	}
	if cfg.FrontendURL != srv.URL {
		t.Errorf("FrontendURL = %q", cfg.FrontendURL)
	}
	if cfg.AmplifyUserAgent != config.DefaultAmplifyUserAgent {
		t.Errorf("AmplifyUserAgent = %q", cfg.AmplifyUserAgent)
	}
}

func TestDiscoverFromSession_BadToken(t *testing.T) {
	s := auth.RawSession{AppClientID: "c", FrontendURL: "https://example.com", IDToken: "not.a.jwt"}
	cfg, err := config.DiscoverFromSession("default", s)
	if cfg != nil {
		t.Errorf("expected nil Config for bad token, got %+v", cfg)
	}
	if err == nil {
		t.Error("expected error for malformed idToken")
	}
}
