package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noperator/chromedb"
)

// Tokens holds the Cognito tokens extracted from Chrome localStorage.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	// Claims parsed from IDToken:
	UserID   string
	GroupIDs []string // parsed from comma-separated JWT claim, empty strings dropped
	Email    string
	Username string // cognito:username
	Expiry   time.Time
}

// RawSession is a Cognito session found in the browser before any validation.
// Each entry is uniquely identified by (FrontendURL, AppClientID).
type RawSession struct {
	AppClientID  string
	FrontendURL  string // origin URL (StorageKey from Chrome localStorage)
	IDToken      string
	AccessToken  string
	RefreshToken string
}

// ErrNoSession is returned when no valid session is found in any browser profile.
var ErrNoSession = errors.New("no TEAM session found in browser localStorage — sign into TEAM in Chrome and try again")

// browserRoots lists the Application Support subdirectory for each supported
// Chromium-family browser on macOS.
var browserRoots = []string{
	"Google/Chrome",
	"Microsoft Edge",
	"BraveSoftware/Brave-Browser",
	"Chromium",
	"Arc/User Data",
}

// FromBrowser scans all Chromium-family browser profiles on macOS and returns
// the first valid Tokens for appClientID.
func FromBrowser(appClientID string) (*Tokens, error) {
	sessions, err := AllSessions()
	if err != nil {
		return nil, err
	}
	return pickValidSession(sessions, appClientID)
}

// AllSessions returns all distinct Cognito sessions found across all Chromium
// browser profiles. Sessions are deduplicated by (FrontendURL, AppClientID).
// Per-directory LevelDB load failures are skipped silently — a single locked
// Chrome profile must not break the whole walk. Returns ErrNoSession if no
// sessions are found across any reachable profile.
func AllSessions() ([]RawSession, error) {
	dirs, err := allLevelDBDirs()
	if err != nil {
		return nil, err
	}
	var all []RawSession
	seen := map[string]bool{}
	for _, dir := range dirs {
		lsd, err := chromedb.LoadLocalStorage(dir)
		if err != nil {
			continue
		}
		for _, s := range cognitoRecordsToRaw(lsd.Records) {
			key := s.FrontendURL + "\x00" + s.AppClientID
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, s)
		}
	}
	if len(all) == 0 {
		return nil, ErrNoSession
	}
	return all, nil
}

// pickValidSession returns the first session whose AppClientID matches and
// whose ID token parses cleanly and is not expired. Sessions that fail
// either check are skipped — a single bad record must not abort the search.
func pickValidSession(sessions []RawSession, appClientID string) (*Tokens, error) {
	for _, s := range sessions {
		if s.AppClientID != appClientID {
			continue
		}
		tokens, err := ParseTokenClaims(s.IDToken, appClientID)
		if err != nil {
			continue
		}
		if time.Now().After(tokens.Expiry) {
			continue
		}
		tokens.AccessToken = s.AccessToken
		tokens.RefreshToken = s.RefreshToken
		return tokens, nil
	}
	return nil, ErrNoSession
}

// ParsePoolID extracts the Cognito user pool ID from the iss claim of an idToken.
// iss format: https://cognito-idp.<region>.amazonaws.com/<region>_<poolId>
func ParsePoolID(idToken string) (string, error) {
	claims, err := parseJWTClaims(idToken)
	if err != nil {
		return "", err
	}
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return "", fmt.Errorf("no iss claim in idToken")
	}
	idx := strings.LastIndexByte(iss, '/')
	if idx < 0 {
		return "", fmt.Errorf("unexpected iss format: %s", iss)
	}
	return iss[idx+1:], nil
}

// ParseTokenClaims parses the JWT claims from idToken, validates the aud
// claim against appClientID, and returns a Tokens struct with all claim
// fields populated. It does NOT check whether the token is expired — that
// is the caller's responsibility.
func ParseTokenClaims(idToken, appClientID string) (*Tokens, error) {
	claims, err := parseJWTClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("parsing idToken: %w", err)
	}
	aud, _ := claims["aud"].(string)
	if aud != appClientID {
		return nil, fmt.Errorf("idToken aud %q != appClientID %q", aud, appClientID)
	}
	expF, _ := claims["exp"].(float64)
	expiry := time.Unix(int64(expF), 0)

	userID, _ := claims["userId"].(string)
	if userID == "" {
		return nil, fmt.Errorf("idToken missing required userId claim")
	}
	groupIDsStr, _ := claims["groupIds"].(string)
	email, _ := claims["email"].(string)
	username, _ := claims["cognito:username"].(string)

	var groupIDs []string
	for _, g := range strings.Split(groupIDsStr, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groupIDs = append(groupIDs, g)
		}
	}

	return &Tokens{
		IDToken:  idToken,
		UserID:   userID,
		GroupIDs: groupIDs,
		Email:    email,
		Username: username,
		Expiry:   expiry,
	}, nil
}

// allLevelDBDirs returns every leveldb directory found across all supported
// Chromium-family browsers and their profile directories on macOS.
// Returns an error if the user's home directory cannot be resolved — that
// is fatal (no filesystem path is reachable). Missing browser dirs are
// silently skipped.
func allLevelDBDirs() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolving home dir: %w", err)
	}
	base := filepath.Join(home, "Library", "Application Support")
	var found []string
	for _, root := range browserRoots {
		dir := filepath.Join(base, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if name != "Default" && !strings.HasPrefix(name, "Profile ") {
				continue
			}
			ldb := filepath.Join(dir, name, "Local Storage", "leveldb")
			if _, err := os.Stat(ldb); err == nil {
				found = append(found, ldb)
			}
		}
	}
	return found, nil
}

// cognitoRecordsToRaw groups localStorage records by (origin, clientID) and
// returns a RawSession for each pair that has a LastAuthUser and idToken.
func cognitoRecordsToRaw(records []chromedb.LocalStorageRecord) []RawSession {
	const prefix = "CognitoIdentityServiceProvider."
	type candidate struct {
		clientID   string
		storageKey string
		lastUser   string
		tokens     map[string]string
	}
	byKey := map[string]*candidate{}
	for _, r := range records {
		if !strings.HasPrefix(r.ScriptKey, prefix) {
			continue
		}
		rest := r.ScriptKey[len(prefix):]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		cID, subkey := rest[:dot], rest[dot+1:]
		mapKey := r.StorageKey + "\x00" + cID
		c, ok := byKey[mapKey]
		if !ok {
			c = &candidate{clientID: cID, storageKey: r.StorageKey, tokens: map[string]string{}}
			byKey[mapKey] = c
		}
		if subkey == "LastAuthUser" {
			c.lastUser = r.Decoded
		}
		c.tokens[subkey] = r.Decoded
	}
	var out []RawSession
	for _, c := range byKey {
		if c.lastUser == "" {
			continue
		}
		idTok := c.tokens[c.lastUser+".idToken"]
		if idTok == "" {
			continue
		}
		out = append(out, RawSession{
			AppClientID:  c.clientID,
			FrontendURL:  c.storageKey,
			IDToken:      idTok,
			AccessToken:  c.tokens[c.lastUser+".accessToken"],
			RefreshToken: c.tokens[c.lastUser+".refreshToken"],
		})
	}
	return out
}

// parseJWTClaims decodes the payload segment of a JWT without verifying the
// signature. Signature verification is handled server-side by AppSync.
func parseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return claims, nil
}
