package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drogers0/awsup/internal/config"
)

func setRequiredEnv(t *testing.T, vals map[string]string) {
	t.Helper()
	for k, v := range vals {
		t.Setenv(k, v)
	}
}

func clearRequiredEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"TEAM_COGNITO_APP_CLIENT_ID",
		"TEAM_APPSYNC_ENDPOINT",
		"TEAM_FRONTEND_URL",
		"TEAM_COGNITO_USER_POOL_ID",
		"TEAM_COGNITO_HOSTED_UI_DOMAIN",
		"TEAM_AMPLIFY_USER_AGENT",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	clearRequiredEnv(t)
	setRequiredEnv(t, map[string]string{
		"TEAM_COGNITO_APP_CLIENT_ID":    "test-client-id",
		"TEAM_APPSYNC_ENDPOINT":         "https://test.appsync.amazonaws.com/graphql",
		"TEAM_FRONTEND_URL":             "https://test.example.com",
		"TEAM_COGNITO_USER_POOL_ID":     "us-east-1_test",
		"TEAM_COGNITO_HOSTED_UI_DOMAIN": "https://auth.test.amazoncognito.com",
	})

	cfg, err := config.Load("test-profile-env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppClientID != "test-client-id" {
		t.Errorf("AppClientID = %q, want %q", cfg.AppClientID, "test-client-id")
	}
	if cfg.AppSyncEndpoint != "https://test.appsync.amazonaws.com/graphql" {
		t.Errorf("AppSyncEndpoint = %q", cfg.AppSyncEndpoint)
	}
	if cfg.FrontendURL != "https://test.example.com" {
		t.Errorf("FrontendURL = %q", cfg.FrontendURL)
	}
	if cfg.AmplifyUserAgent != config.DefaultAmplifyUserAgent {
		t.Errorf("AmplifyUserAgent default = %q, want %q", cfg.AmplifyUserAgent, config.DefaultAmplifyUserAgent)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	clearRequiredEnv(t)

	_, err := config.Load("__nonexistent_profile_xyzzy__")
	if err == nil {
		t.Fatal("expected error for missing vars, got nil")
	}
	for _, want := range []string{"TEAM_COGNITO_APP_CLIENT_ID", "TEAM_APPSYNC_ENDPOINT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing expected var %q", err.Error(), want)
		}
	}
}

func TestLoad_HostedUIDomain_PrependHTTPS(t *testing.T) {
	clearRequiredEnv(t)
	setRequiredEnv(t, map[string]string{
		"TEAM_COGNITO_APP_CLIENT_ID":    "cid",
		"TEAM_APPSYNC_ENDPOINT":         "https://appsync.example.com/graphql",
		"TEAM_FRONTEND_URL":             "https://frontend.example.com",
		"TEAM_COGNITO_USER_POOL_ID":     "us-east-1_pool",
		"TEAM_COGNITO_HOSTED_UI_DOMAIN": "auth.example.amazoncognito.com",
	})

	cfg, err := config.Load("test-profile-https")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HostedUIDomain != "https://auth.example.amazoncognito.com" {
		t.Errorf("HostedUIDomain = %q, want https:// prefix", cfg.HostedUIDomain)
	}
}

func TestProfileList_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	profiles, err := config.ProfileList()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected empty profiles, got %v", profiles)
	}
}

func TestProfileList_WithFiles(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfgDir := filepath.Join(tmpDir, ".config", "awsup")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"default.env", "staging.env"} {
		if err := os.WriteFile(filepath.Join(cfgDir, name), []byte("# empty\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	profiles, err := config.ProfileList()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %v", profiles)
	}
}
