package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultAmplifyUserAgent is the Amplify user-agent string sent with every
// AppSync request when TEAM_AMPLIFY_USER_AGENT is not set.
const DefaultAmplifyUserAgent = "aws-amplify/5.3.26 api/1 framework/1"

// Config holds all deployment-specific settings for one TEAM profile.
type Config struct {
	Profile          string
	AppClientID      string // TEAM_COGNITO_APP_CLIENT_ID
	AppSyncEndpoint  string // TEAM_APPSYNC_ENDPOINT
	FrontendURL      string // TEAM_FRONTEND_URL
	UserPoolID       string // TEAM_COGNITO_USER_POOL_ID
	HostedUIDomain   string // TEAM_COGNITO_HOSTED_UI_DOMAIN (full base URL)
	AmplifyUserAgent string // TEAM_AMPLIFY_USER_AGENT
}

// CachePath returns the token cache file path for this profile.
// Precondition: Load (or auth.AllSessions) must have already succeeded —
// both fail fast if os.UserHomeDir errors, so home is guaranteed resolvable
// by the time this is called.
func (c *Config) CachePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "awsup", c.Profile+".credentials")
}

// EnvFilePath returns the profile env file path. See CachePath for the
// precondition on home-dir resolvability.
func (c *Config) EnvFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "awsup", c.Profile+".env")
}

// Load loads the config for profile using the search order:
//  1. Environment variable
//  2. ~/.config/awsup/<profile>.env
//  3. ./.env in current working directory
func Load(profile string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolving home dir: %w", err)
	}
	profileEnvPath := filepath.Join(home, ".config", "awsup", profile+".env")

	profileVars := readEnvFile(profileEnvPath)
	cwdVars := readEnvFile(".env")

	get := func(name string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		if v := profileVars[name]; v != "" {
			return v
		}
		return cwdVars[name]
	}

	cfg := &Config{
		Profile:          profile,
		AppClientID:      get("TEAM_COGNITO_APP_CLIENT_ID"),
		AppSyncEndpoint:  get("TEAM_APPSYNC_ENDPOINT"),
		FrontendURL:      get("TEAM_FRONTEND_URL"),
		UserPoolID:       get("TEAM_COGNITO_USER_POOL_ID"),
		HostedUIDomain:   get("TEAM_COGNITO_HOSTED_UI_DOMAIN"),
		AmplifyUserAgent: get("TEAM_AMPLIFY_USER_AGENT"),
	}

	if cfg.AmplifyUserAgent == "" {
		cfg.AmplifyUserAgent = DefaultAmplifyUserAgent
	}

	// Normalize HostedUIDomain: ensure scheme is present.
	if cfg.HostedUIDomain != "" &&
		!strings.HasPrefix(cfg.HostedUIDomain, "https://") &&
		!strings.HasPrefix(cfg.HostedUIDomain, "http://") {
		cfg.HostedUIDomain = "https://" + cfg.HostedUIDomain
	}

	var missing []string
	if cfg.AppClientID == "" {
		missing = append(missing, "TEAM_COGNITO_APP_CLIENT_ID")
	}
	if cfg.AppSyncEndpoint == "" {
		missing = append(missing, "TEAM_APPSYNC_ENDPOINT")
	}
	if cfg.FrontendURL == "" {
		missing = append(missing, "TEAM_FRONTEND_URL")
	}
	if cfg.UserPoolID == "" {
		missing = append(missing, "TEAM_COGNITO_USER_POOL_ID")
	}
	if cfg.HostedUIDomain == "" {
		missing = append(missing, "TEAM_COGNITO_HOSTED_UI_DOMAIN")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required config vars: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

// ProfileList returns all profile names found in ~/.config/awsup/ (*.env files).
func ProfileList() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "awsup")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading config dir: %w", err)
	}
	var profiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".env") {
			profiles = append(profiles, strings.TrimSuffix(e.Name(), ".env"))
		}
	}
	return profiles, nil
}

// readEnvFile reads a KEY=VALUE env file. Lines starting with # and empty
// lines are ignored. Supports optional "export " prefix and quoted values.
func readEnvFile(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 &&
			((val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		m[key] = val
	}
	return m
}
