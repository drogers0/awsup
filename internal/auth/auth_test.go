package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noperator/chromedb"
)

// makeJWT builds a minimal synthetic JWT with the given payload claims.
// The signature segment is set to "fakesig" — we never verify signatures.
func makeJWT(payload map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	p, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s.fakesig", header, base64.RawURLEncoding.EncodeToString(p)), nil
}

func TestParseJWTClaims_Valid(t *testing.T) {
	payload := map[string]any{
		"aud":              "client-abc",
		"sub":              "sub-123",
		"email":            "user@example.com",
		"userId":           "uid-456",
		"groupIds":         "g1,g2,g3,",
		"cognito:username": "coguser",
		"exp":              float64(9999999999),
	}
	jwt, err := makeJWT(payload)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := parseJWTClaims(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["email"] != "user@example.com" {
		t.Errorf("email: got %v", claims["email"])
	}
	if claims["userId"] != "uid-456" {
		t.Errorf("userId: got %v", claims["userId"])
	}
	if claims["cognito:username"] != "coguser" {
		t.Errorf("cognito:username: got %v", claims["cognito:username"])
	}
}

func TestParseJWTClaims_InvalidFormat(t *testing.T) {
	_, err := parseJWTClaims("not.a.valid.jwt.with.too.many.parts")
	if err == nil {
		t.Fatal("expected error for token with wrong number of parts")
	}
	_, err2 := parseJWTClaims("onlyone")
	if err2 == nil {
		t.Fatal("expected error for token with no dots")
	}
}

func TestParseJWTClaims_InvalidBase64(t *testing.T) {
	// Construct a token with a non-base64 payload segment.
	bad := "eyJhbGciOiJSUzI1NiJ9.!!!notbase64!!!.fakesig"
	_, err := parseJWTClaims(bad)
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestParseTokenClaims_Valid(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	payload := map[string]any{
		"aud":              "app-client-1",
		"email":            "david@example.com",
		"userId":           "user-999",
		"groupIds":         "grp-a, grp-b,,",
		"cognito:username": "idc_david",
		"exp":              float64(exp),
	}
	jwt, err := makeJWT(payload)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := ParseTokenClaims(jwt, "app-client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.UserID != "user-999" {
		t.Errorf("UserID: got %q", tokens.UserID)
	}
	if tokens.Email != "david@example.com" {
		t.Errorf("Email: got %q", tokens.Email)
	}
	if tokens.Username != "idc_david" {
		t.Errorf("Username: got %q", tokens.Username)
	}
	// groupIds: "grp-a, grp-b,," → ["grp-a","grp-b"] (spaces trimmed, empty strings dropped)
	if len(tokens.GroupIDs) != 2 {
		t.Errorf("GroupIDs: got %v, want 2 elements", tokens.GroupIDs)
	}
	if tokens.GroupIDs[0] != "grp-a" || tokens.GroupIDs[1] != "grp-b" {
		t.Errorf("GroupIDs: got %v", tokens.GroupIDs)
	}
	if tokens.IDToken != jwt {
		t.Errorf("IDToken not preserved")
	}
	// Expiry should be set (not zero)
	if tokens.Expiry.IsZero() {
		t.Error("Expiry is zero")
	}
}

func TestParseTokenClaims_AudMismatch(t *testing.T) {
	payload := map[string]any{
		"aud": "wrong-client",
		"exp": float64(9999999999),
	}
	jwt, err := makeJWT(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseTokenClaims(jwt, "expected-client")
	if err == nil {
		t.Fatal("expected error for aud mismatch")
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Errorf("error should mention aud: %v", err)
	}
}

func TestParseTokenClaims_DoesNotCheckExpiry(t *testing.T) {
	// ParseTokenClaims must NOT reject expired tokens — tokencache decides that.
	payload := map[string]any{
		"aud":    "my-client",
		"userId": "u1",
		"exp":    float64(1), // Unix epoch + 1s — definitely expired
	}
	jwt, err := makeJWT(payload)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := ParseTokenClaims(jwt, "my-client")
	if err != nil {
		t.Fatalf("ParseTokenClaims should not reject expired tokens, got: %v", err)
	}
	if tokens.Expiry.Unix() != 1 {
		t.Errorf("Expiry: got %v, want Unix 1", tokens.Expiry)
	}
}

func TestParseTokenClaims_GroupIDsWithSpaces(t *testing.T) {
	payload := map[string]any{
		"aud":    "client-1",
		"userId": "u1",
		"exp":    float64(9999999999),
		// spaces around entries and trailing comma
		"groupIds": " g1 , g2 , , g3",
	}
	jwt, err := makeJWT(payload)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := ParseTokenClaims(jwt, "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"g1", "g2", "g3"}
	if len(tokens.GroupIDs) != len(want) {
		t.Fatalf("GroupIDs: got %v, want %v", tokens.GroupIDs, want)
	}
	for i, g := range tokens.GroupIDs {
		if g != want[i] {
			t.Errorf("GroupIDs[%d]: got %q, want %q", i, g, want[i])
		}
	}
}

func TestParseTokenClaims_MissingUserID(t *testing.T) {
	payload := map[string]any{
		"aud": "client-1",
		"exp": float64(9999999999),
		// no userId claim
	}
	jwt, err := makeJWT(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseTokenClaims(jwt, "client-1")
	if err == nil {
		t.Fatal("expected error for missing userId, got nil")
	}
	if !strings.Contains(err.Error(), "userId") {
		t.Errorf("error should mention userId: %v", err)
	}
}

func TestFromBrowser_NoBrowserDirs(t *testing.T) {
	// Override HOME to a temp dir with no browser profiles.
	t.Setenv("HOME", t.TempDir())

	_, err := FromBrowser("any-client-id")
	if !errors.Is(err, ErrNoSession) {
		t.Errorf("expected ErrNoSession, got: %v", err)
	}
}

func TestAllSessions_NoSessions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := AllSessions()
	if !errors.Is(err, ErrNoSession) {
		t.Errorf("expected ErrNoSession, got: %v", err)
	}
}

func TestPickValidSession_SkipsBadSessions(t *testing.T) {
	validJWT, _ := makeJWT(map[string]any{
		"aud":    "wanted-client",
		"userId": "u1",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	expiredJWT, _ := makeJWT(map[string]any{
		"aud":    "wanted-client",
		"userId": "u1",
		"exp":    float64(1), // long expired
	})
	mismatchedAud, _ := makeJWT(map[string]any{
		"aud":    "different-client",
		"userId": "u1",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})

	sessions := []RawSession{
		{AppClientID: "other-client", IDToken: validJWT},       // wrong clientID — skip
		{AppClientID: "wanted-client", IDToken: "not.a.jwt"},   // malformed — skip
		{AppClientID: "wanted-client", IDToken: expiredJWT},    // expired — skip
		{AppClientID: "wanted-client", IDToken: mismatchedAud}, // aud mismatch — skip
		{AppClientID: "wanted-client", IDToken: validJWT, AccessToken: "a", RefreshToken: "r"},
	}
	tokens, err := pickValidSession(sessions, "wanted-client")
	if err != nil {
		t.Fatalf("expected valid session, got error: %v", err)
	}
	if tokens.AccessToken != "a" || tokens.RefreshToken != "r" {
		t.Errorf("expected access/refresh tokens to be plumbed through, got %+v", tokens)
	}
}

func TestPickValidSession_NoMatch(t *testing.T) {
	if _, err := pickValidSession(nil, "anything"); !errors.Is(err, ErrNoSession) {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}

func TestCognitoRecordsToRaw(t *testing.T) {
	const prefix = "CognitoIdentityServiceProvider."

	makeRec := func(origin, scriptKey, value string) chromedb.LocalStorageRecord {
		return chromedb.LocalStorageRecord{StorageKey: origin, ScriptKey: scriptKey, Decoded: value}
	}

	t.Run("empty", func(t *testing.T) {
		if got := cognitoRecordsToRaw(nil); len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("no cognito prefix", func(t *testing.T) {
		recs := []chromedb.LocalStorageRecord{
			makeRec("https://example.com", "someOtherKey", "val"),
		}
		if got := cognitoRecordsToRaw(recs); len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("missing LastAuthUser", func(t *testing.T) {
		idTok, _ := makeJWT(map[string]any{"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Test"})
		recs := []chromedb.LocalStorageRecord{
			makeRec("https://a.com", prefix+"cid1.alice.idToken", idTok),
		}
		if got := cognitoRecordsToRaw(recs); len(got) != 0 {
			t.Errorf("expected empty (no LastAuthUser), got %v", got)
		}
	})

	t.Run("missing idToken", func(t *testing.T) {
		recs := []chromedb.LocalStorageRecord{
			makeRec("https://a.com", prefix+"cid1.LastAuthUser", "alice"),
			makeRec("https://a.com", prefix+"cid1.alice.accessToken", "tok"),
		}
		if got := cognitoRecordsToRaw(recs); len(got) != 0 {
			t.Errorf("expected empty (no idToken), got %v", got)
		}
	})

	t.Run("two clients same origin", func(t *testing.T) {
		idA, _ := makeJWT(map[string]any{"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_PoolA"})
		idB, _ := makeJWT(map[string]any{"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_PoolB"})
		recs := []chromedb.LocalStorageRecord{
			makeRec("https://team.example.com", prefix+"clientA.LastAuthUser", "alice"),
			makeRec("https://team.example.com", prefix+"clientA.alice.idToken", idA),
			makeRec("https://team.example.com", prefix+"clientB.LastAuthUser", "bob"),
			makeRec("https://team.example.com", prefix+"clientB.bob.idToken", idB),
		}
		got := cognitoRecordsToRaw(recs)
		if len(got) != 2 {
			t.Fatalf("expected 2 sessions, got %d: %v", len(got), got)
		}
	})

	t.Run("same client different origins", func(t *testing.T) {
		idA, _ := makeJWT(map[string]any{"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Pool"})
		idB, _ := makeJWT(map[string]any{"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Pool"})
		recs := []chromedb.LocalStorageRecord{
			makeRec("https://prod.example.com", prefix+"sharedClient.LastAuthUser", "alice"),
			makeRec("https://prod.example.com", prefix+"sharedClient.alice.idToken", idA),
			makeRec("https://staging.example.com", prefix+"sharedClient.LastAuthUser", "bob"),
			makeRec("https://staging.example.com", prefix+"sharedClient.bob.idToken", idB),
		}
		got := cognitoRecordsToRaw(recs)
		if len(got) != 2 {
			t.Fatalf("expected 2 sessions (one per origin), got %d: %v", len(got), got)
		}
	})

	t.Run("access and refresh tokens populated", func(t *testing.T) {
		idTok, _ := makeJWT(map[string]any{"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Pool"})
		recs := []chromedb.LocalStorageRecord{
			makeRec("https://team.example.com", prefix+"cid.LastAuthUser", "alice"),
			makeRec("https://team.example.com", prefix+"cid.alice.idToken", idTok),
			makeRec("https://team.example.com", prefix+"cid.alice.accessToken", "access-tok"),
			makeRec("https://team.example.com", prefix+"cid.alice.refreshToken", "refresh-tok"),
		}
		got := cognitoRecordsToRaw(recs)
		if len(got) != 1 {
			t.Fatalf("expected 1 session, got %d", len(got))
		}
		s := got[0]
		if s.AccessToken != "access-tok" {
			t.Errorf("AccessToken = %q, want %q", s.AccessToken, "access-tok")
		}
		if s.RefreshToken != "refresh-tok" {
			t.Errorf("RefreshToken = %q, want %q", s.RefreshToken, "refresh-tok")
		}
		if s.FrontendURL != "https://team.example.com" {
			t.Errorf("FrontendURL = %q", s.FrontendURL)
		}
		if s.AppClientID != "cid" {
			t.Errorf("AppClientID = %q", s.AppClientID)
		}
	})
}
