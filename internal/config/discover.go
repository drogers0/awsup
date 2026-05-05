package config

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/drogers0/awsup/internal/auth"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

var (
	appSyncRe    = regexp.MustCompile(`https://[a-z0-9]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com/graphql`)
	cognitoDomRe = regexp.MustCompile(`[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com`)
	jsBundleRe   = regexp.MustCompile(`src="(/static/js/main\.[^"]+\.js)"`)
)

const maxFetchBytes = 10 << 20 // 10 MB

// DiscoverFromSession builds a Config from a browser RawSession.
// AppClientID, UserPoolID, and FrontendURL are derived without network access.
// AppSyncEndpoint and HostedUIDomain require fetching the frontend's JS bundle.
// If those fields cannot be populated they are left empty and an error describing
// what is missing is returned alongside the partially-populated Config.
func DiscoverFromSession(profile string, s auth.RawSession) (*Config, error) {
	poolID, err := auth.ParsePoolID(s.IDToken)
	if err != nil {
		return nil, fmt.Errorf("parsing idToken: %w", err)
	}
	cfg := &Config{
		Profile:          profile,
		AppClientID:      s.AppClientID,
		FrontendURL:      s.FrontendURL,
		UserPoolID:       poolID,
		AmplifyUserAgent: DefaultAmplifyUserAgent,
	}

	appSync, hostedUI, fetchErr := fetchAmplifyURLs(s.FrontendURL)
	cfg.AppSyncEndpoint = appSync
	cfg.HostedUIDomain = hostedUI

	if fetchErr != nil {
		return cfg, fetchErr
	}
	var missing []string
	if cfg.AppSyncEndpoint == "" {
		missing = append(missing, "TEAM_APPSYNC_ENDPOINT")
	}
	if cfg.HostedUIDomain == "" {
		missing = append(missing, "TEAM_COGNITO_HOSTED_UI_DOMAIN")
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("could not discover: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

// fetchAmplifyURLs fetches the frontend's index.html, locates the main JS bundle,
// and extracts the AppSync endpoint and Cognito hosted UI domain via regex.
// Returns empty strings (not errors) when a pattern is not found in the bundle.
// HostedUIDomain is returned with the https:// scheme included.
func fetchAmplifyURLs(frontendURL string) (appSyncEndpoint, hostedUIDomain string, err error) {
	base := strings.TrimRight(frontendURL, "/")
	indexBody, err := getBody(base + "/index.html")
	if err != nil {
		return "", "", fmt.Errorf("fetching index.html: %w", err)
	}
	m := jsBundleRe.FindSubmatch(indexBody)
	if m == nil {
		return "", "", fmt.Errorf("no JS bundle found in index.html")
	}
	jsBody, err := getBody(base + string(m[1]))
	if err != nil {
		return "", "", fmt.Errorf("fetching JS bundle: %w", err)
	}
	if ep := appSyncRe.Find(jsBody); ep != nil {
		appSyncEndpoint = string(ep)
	}
	if d := cognitoDomRe.Find(jsBody); d != nil {
		hostedUIDomain = "https://" + string(d)
	}
	return appSyncEndpoint, hostedUIDomain, nil
}

func getBody(url string) ([]byte, error) {
	resp, err := httpClient.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
}
