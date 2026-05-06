package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drogers0/awsup/internal/appsync"
	"github.com/drogers0/awsup/internal/policy"
	"github.com/drogers0/awsup/internal/tokencache"
)

// binPath is the path to the compiled test binary, set once in TestMain.
var binPath string

func TestMain(m *testing.M) {
	tmp := os.TempDir()
	binPath = filepath.Join(tmp, "awsup-test-bin")
	out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
	if err != nil {
		panic("build failed: " + string(out))
	}
	code := m.Run()
	os.Remove(binPath)
	os.Exit(code)
}

func runBin(args ...string) (stdout, stderr string, exitCode int) {
	return runBinEnv(nil, args...)
}

func runBinEnvInput(extraEnv []string, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// runBinEnv runs the test binary with extra environment overrides appended
// to the parent environment.
func runBinEnv(extraEnv []string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestParseArgs_Help(t *testing.T) {
	out, _, code := runBin("--help")
	if code != 0 {
		t.Errorf("--help: expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "awsup") {
		t.Errorf("--help: expected usage text in stdout, got %q", out)
	}
}

func TestParseArgs_Version(t *testing.T) {
	out, _, code := runBin("--version")
	if code != 0 {
		t.Errorf("--version: expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "awsup") {
		t.Errorf("--version: expected 'awsup' in output, got %q", out)
	}
}

// TestParseArgs_ProfileFlag verifies --profile is consumed before subcommand
// dispatch: "team --profile staging request --help" should exit 0 because
// --help is handled by the request subcommand's flag set, not rejected as an
// unknown command.
func TestParseArgs_ProfileFlag(t *testing.T) {
	_, _, code := runBin("--profile", "staging", "request", "--help")
	if code != 0 {
		t.Errorf("--profile staging request --help: expected exit 0, got %d", code)
	}
}

func TestParseArgs_UnknownCommand(t *testing.T) {
	_, stderr, code := runBin("notacommand")
	if code == 0 {
		t.Errorf("unknown command: expected non-zero exit, got 0")
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("unknown command: expected 'unknown command' in stderr, got %q", stderr)
	}
}

func TestResolveByIDOrName_AccountByID(t *testing.T) {
	accounts := []policy.Account{
		{Name: "Production", ID: "123456789012"},
		{Name: "Staging", ID: "999999999999"},
	}
	id, name, ok := resolveByIDOrName(accounts, "123456789012", accountKey)
	if !ok {
		t.Fatal("expected ok=true for exact ID match")
	}
	if id != "123456789012" || name != "Production" {
		t.Errorf("got id=%q name=%q", id, name)
	}
}

func TestResolveByIDOrName_AccountByName(t *testing.T) {
	accounts := []policy.Account{{Name: "Production", ID: "123456789012"}}
	id, name, ok := resolveByIDOrName(accounts, "production", accountKey)
	if !ok {
		t.Fatal("expected ok=true for case-insensitive name match")
	}
	if id != "123456789012" || name != "Production" {
		t.Errorf("got id=%q name=%q", id, name)
	}
}

func TestResolveByIDOrName_RoleByID(t *testing.T) {
	perms := []policy.Permission{{Name: "ReadOnly", ID: "arn:aws:sso:::permissionSet/ssoins/ps-abc"}}
	id, name, ok := resolveByIDOrName(perms, "arn:aws:sso:::permissionSet/ssoins/ps-abc", permissionKey)
	if !ok {
		t.Fatal("expected ok=true for exact ID match")
	}
	if id != "arn:aws:sso:::permissionSet/ssoins/ps-abc" || name != "ReadOnly" {
		t.Errorf("got id=%q name=%q", id, name)
	}
}

func TestResolveByIDOrName_RoleByName(t *testing.T) {
	perms := []policy.Permission{{Name: "ReadOnly", ID: "arn:aws:sso:::permissionSet/ssoins/ps-abc"}}
	id, name, ok := resolveByIDOrName(perms, "readonly", permissionKey)
	if !ok {
		t.Fatal("expected ok=true for case-insensitive name match")
	}
	if id != "arn:aws:sso:::permissionSet/ssoins/ps-abc" || name != "ReadOnly" {
		t.Errorf("got id=%q name=%q", id, name)
	}
}

func TestResolveByIDOrName_NotFound(t *testing.T) {
	accounts := []policy.Account{{Name: "Production", ID: "123456789012"}}
	if _, _, ok := resolveByIDOrName(accounts, "nonexistent", accountKey); ok {
		t.Fatal("expected ok=false for no match")
	}
}

func TestResolveByIDOrName_EmptyList(t *testing.T) {
	if _, _, ok := resolveByIDOrName[policy.Account](nil, "anything", accountKey); ok {
		t.Fatal("expected ok=false for nil slice")
	}
}

func TestApplyRealtimeDirectGrantChoices_FullPayload(t *testing.T) {
	ent := &policy.Policy{
		Accounts:    []policy.Account{{ID: "123456789012", Name: "Prod"}},
		Permissions: []policy.Permission{{ID: "arn:perm", Name: "ReadOnly"}},
	}
	acctID, acctName, roleID, roleName := applyRealtimeDirectGrantChoices("", "", ent)
	if acctID != "123456789012" || acctName != "Prod" {
		t.Fatalf("unexpected account resolution: %s %s", acctID, acctName)
	}
	if roleID != "arn:perm" || roleName != "ReadOnly" {
		t.Fatalf("unexpected role resolution: %s %s", roleID, roleName)
	}
}

func TestApplyRealtimeDirectGrantChoices_PartialPayload(t *testing.T) {
	ent := &policy.Policy{Accounts: []policy.Account{{ID: "123456789012", Name: "Prod"}}}
	acctID, acctName, roleID, roleName := applyRealtimeDirectGrantChoices("", "", ent)
	if acctID != "123456789012" || acctName != "Prod" {
		t.Fatalf("unexpected account resolution: %s %s", acctID, acctName)
	}
	if roleID != "" || roleName != "" {
		t.Fatalf("expected missing role for partial payload, got %s %s", roleID, roleName)
	}
}

func TestApplyRealtimeDirectGrantChoices_PreservesProvidedFlags(t *testing.T) {
	ent := &policy.Policy{
		Accounts:    []policy.Account{{ID: "123456789012", Name: "Prod"}},
		Permissions: []policy.Permission{{ID: "arn:perm", Name: "ReadOnly"}},
	}
	acctID, acctName, roleID, roleName := applyRealtimeDirectGrantChoices("Prod", "ReadOnly", ent)
	if acctID != "123456789012" || roleID != "arn:perm" {
		t.Fatalf("expected provided names to resolve to IDs, got %s %s", acctID, roleID)
	}
	if acctName != "Prod" || roleName != "ReadOnly" {
		t.Fatalf("expected resolved display names, got %s %s", acctName, roleName)
	}
}

func TestResolveDirectGrantFromRealtime_SkipsWhenFlagsComplete(t *testing.T) {
	orig := getRealtimeEntitlements
	defer func() { getRealtimeEntitlements = orig }()
	called := false
	getRealtimeEntitlements = func(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*policy.Policy, error) {
		called = true
		return nil, nil
	}
	acctID, _, roleID, _, err := resolveDirectGrantFromRealtime(context.Background(), nil, "u1", nil, "123456789012", "arn:role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("expected realtime lookup to be skipped")
	}
	if acctID != "123456789012" || roleID != "arn:role" {
		t.Fatalf("unexpected IDs: %s %s", acctID, roleID)
	}
}

func TestResolveDirectGrantFromRealtime_PartialResult(t *testing.T) {
	orig := getRealtimeEntitlements
	defer func() { getRealtimeEntitlements = orig }()
	getRealtimeEntitlements = func(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*policy.Policy, error) {
		return &policy.Policy{Accounts: []policy.Account{{ID: "123", Name: "Prod"}}}, nil
	}
	acctID, acctName, roleID, roleName, err := resolveDirectGrantFromRealtime(context.Background(), nil, "u1", nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acctID != "123" || acctName != "Prod" {
		t.Fatalf("unexpected account result: %s %s", acctID, acctName)
	}
	if roleID != "" || roleName != "" {
		t.Fatalf("expected unresolved role for partial result, got %s %s", roleID, roleName)
	}
}

func TestResolveDirectGrantFromRealtime_TimeoutError(t *testing.T) {
	orig := getRealtimeEntitlements
	defer func() { getRealtimeEntitlements = orig }()
	getRealtimeEntitlements = func(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*policy.Policy, error) {
		return nil, context.DeadlineExceeded
	}
	acctID, _, roleID, _, err := resolveDirectGrantFromRealtime(context.Background(), nil, "u1", nil, "", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if acctID != "" || roleID != "" {
		t.Fatalf("expected unresolved fields on timeout, got %s %s", acctID, roleID)
	}
}

func TestRequestDirectFallback_RealtimeTimeout(t *testing.T) {
	orig := getRealtimeEntitlements
	defer func() { getRealtimeEntitlements = orig }()
	getRealtimeEntitlements = func(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*policy.Policy, error) {
		return nil, context.DeadlineExceeded
	}
	acctID, acctName, roleID, roleName, err := resolveDirectGrantFromRealtime(context.Background(), nil, "u1", nil, "", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if acctID != "" || acctName != "" || roleID != "" || roleName != "" {
		t.Fatalf("expected unresolved fields on timeout, got %q %q %q %q", acctID, acctName, roleID, roleName)
	}
}

func TestRequestDirectFallback_PartialRealtimeResolve(t *testing.T) {
	orig := getRealtimeEntitlements
	defer func() { getRealtimeEntitlements = orig }()
	getRealtimeEntitlements = func(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*policy.Policy, error) {
		return &policy.Policy{Permissions: []policy.Permission{{ID: "arn:perm", Name: "ReadOnly"}}}, nil
	}
	acctID, acctName, roleID, roleName, err := resolveDirectGrantFromRealtime(context.Background(), nil, "u1", nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acctID != "" || acctName != "" {
		t.Fatalf("expected account unresolved for partial realtime data, got %q %q", acctID, acctName)
	}
	if roleID != "arn:perm" || roleName != "ReadOnly" {
		t.Fatalf("expected role from realtime data, got %q %q", roleID, roleName)
	}
}

func TestRequestDirectFallback_RealtimeSuccessFullResolution(t *testing.T) {
	orig := getRealtimeEntitlements
	defer func() { getRealtimeEntitlements = orig }()
	getRealtimeEntitlements = func(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*policy.Policy, error) {
		return &policy.Policy{
			Accounts:    []policy.Account{{ID: "123", Name: "Prod"}},
			Permissions: []policy.Permission{{ID: "arn:perm", Name: "ReadOnly"}},
		}, nil
	}
	acctID, acctName, roleID, roleName, err := resolveDirectGrantFromRealtime(context.Background(), nil, "u1", nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acctID != "123" || acctName != "Prod" || roleID != "arn:perm" || roleName != "ReadOnly" {
		t.Fatalf("unexpected full realtime resolution: %q %q %q %q", acctID, acctName, roleID, roleName)
	}
}

func TestLooksLikeRawIDs(t *testing.T) {
	cases := []struct {
		accountID, roleID string
		want              bool
	}{
		{"123456789012", "arn:aws:sso:::permissionSet/ssoins-abc/ps-xyz", true},
		{"123456789012", "arn:", true},
		{"123456789012", "VU_PowerUserAccess", false},
		{"123456789012", "", false},
		{"12345678901", "arn:role", false},  // 11 digits
		{"1234567890123", "arn:role", false}, // 13 digits
		{"", "arn:role", false},
		{"123456789abc", "arn:role", false}, // non-numeric
		{"", "", false},
	}
	for _, c := range cases {
		got := looksLikeRawIDs(c.accountID, c.roleID)
		if got != c.want {
			t.Errorf("looksLikeRawIDs(%q, %q) = %v, want %v", c.accountID, c.roleID, got, c.want)
		}
	}
}

func TestFormatChoices(t *testing.T) {
	accounts := []policy.Account{
		{Name: "Production", ID: "123456789012"},
		{Name: "Staging", ID: "999999999999"},
	}
	got := formatChoices(accounts, accountKey)
	want := "Production (123456789012), Staging (999999999999)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---- runRequest integration test fixtures ----

// makeJWT builds an unsigned JWT with the given payload claims.
func makeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s.%s.fakesig", header, base64.RawURLEncoding.EncodeToString(p))
}

// requestServer is a fake AppSync that dispatches by GraphQL operation name
// and records every request body it sees.
type requestServer struct {
	srv          *httptest.Server
	mu           sync.Mutex
	bodies       []string
	createdInput map[string]any
}

func newRequestServer(t *testing.T, accountID, accountName, roleID, roleName string) *requestServer {
	t.Helper()
	rs := &requestServer{}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rs.mu.Lock()
		rs.bodies = append(rs.bodies, string(body))
		rs.mu.Unlock()

		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "GetSettings"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"getSettings": map[string]any{
					"id": "settings", "duration": "8", "expiry": "30",
					"comments": false, "ticketNo": false, "approval": false,
				},
			}})
		case strings.Contains(req.Query, "GetUserPolicy"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"getUserPolicy": map[string]any{
					"id": "u1", "username": "user@example.com",
					"policy": map[string]any{
						"accounts":    []map[string]any{{"id": accountID, "name": accountName}},
						"permissions": []map[string]any{{"id": roleID, "name": roleName}},
					},
				},
			}})
		case strings.Contains(req.Query, "ValidateRequest"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"validateRequest": map[string]any{"valid": true, "reason": ""},
			}})
		case strings.Contains(req.Query, "CreateRequests"):
			input, _ := req.Variables["input"].(map[string]any)
			rs.mu.Lock()
			rs.createdInput = input
			rs.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"createRequests": map[string]any{
					"id": "req-1", "status": "pending",
					"accountId": input["accountId"], "accountName": input["accountName"],
					"role": input["role"], "roleId": input["roleId"],
				},
			}})
		default:
			http.Error(w, "unknown query: "+req.Query, 400)
		}
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func newDirectGrantServer(t *testing.T) *requestServer {
	t.Helper()
	rs := &requestServer{}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rs.mu.Lock()
		rs.bodies = append(rs.bodies, string(body))
		rs.mu.Unlock()

		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "GetSettings"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"getSettings": map[string]any{
					"id": "settings", "duration": "8", "expiry": "30",
					"comments": false, "ticketNo": false, "approval": false,
				},
			}})
		case strings.Contains(req.Query, "GetUserPolicy"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"getUserPolicy": map[string]any{"id": "u1", "username": "user@example.com", "policy": nil},
			}})
		case strings.Contains(req.Query, "ValidateRequest"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"validateRequest": map[string]any{"valid": true, "reason": ""},
			}})
		case strings.Contains(req.Query, "CreateRequests"):
			input, _ := req.Variables["input"].(map[string]any)
			rs.mu.Lock()
			rs.createdInput = input
			rs.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"createRequests": map[string]any{
					"id": "req-1", "status": "pending",
					"accountId": input["accountId"], "accountName": input["accountName"],
					"role": input["role"], "roleId": input["roleId"],
				},
			}})
		default:
			http.Error(w, "unknown query: "+req.Query, 400)
		}
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *requestServer) sawOperation(name string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, b := range rs.bodies {
		if strings.Contains(b, name) {
			return true
		}
	}
	return false
}

// setupRequestEnv writes default.env + default.credentials inside home and
// returns the env override slice for runBinEnv.
func setupRequestEnv(t *testing.T, home, serverURL, clientID, poolID string) []string {
	t.Helper()
	cfgDir := filepath.Join(home, ".config", "awsup")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	envContent := strings.Join([]string{
		"TEAM_COGNITO_APP_CLIENT_ID=" + clientID,
		"TEAM_APPSYNC_ENDPOINT=" + serverURL,
		"TEAM_FRONTEND_URL=" + serverURL,
		"TEAM_COGNITO_USER_POOL_ID=" + poolID,
		"TEAM_COGNITO_HOSTED_UI_DOMAIN=" + serverURL,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "default.env"), []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}

	idToken := makeJWT(t, map[string]any{
		"aud":              clientID,
		"exp":              float64(time.Now().Add(1 * time.Hour).Unix()),
		"userId":           "user-1",
		"groupIds":         "g1",
		"email":            "user@example.com",
		"cognito:username": "user@example.com",
	})
	cache := tokencache.Cache{
		IDToken:     idToken,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		AppClientID: clientID,
		UserPoolID:  poolID,
		UserID:      "user-1",
		GroupIDs:    []string{"g1"},
		Email:       "user@example.com",
		Username:    "user@example.com",
	}
	cacheBytes, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "default.credentials"), cacheBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"HOME=" + home}
}

func TestRequest_AllFlagsResolveNames(t *testing.T) {
	home := t.TempDir()
	rs := newRequestServer(t, "123456789012", "Production",
		"arn:aws:sso:::permissionSet/ssoins/ps-abc", "ReadOnly")
	env := setupRequestEnv(t, home, rs.srv.URL, "test-client", "us-east-1_pool")

	stdout, stderr, code := runBinEnv(env,
		"request",
		"--account", "Production",
		"--role", "ReadOnly",
		"--duration", "4",
		"--justification", "x",
		"--yes",
	)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.createdInput == nil {
		t.Fatal("createRequests was never called")
	}
	if got := rs.createdInput["accountId"]; got != "123456789012" {
		t.Errorf("accountId: got %v, want 123456789012 (name was not resolved to ID)", got)
	}
	if got := rs.createdInput["accountName"]; got != "Production" {
		t.Errorf("accountName: got %v, want Production", got)
	}
	if got := rs.createdInput["roleId"]; got != "arn:aws:sso:::permissionSet/ssoins/ps-abc" {
		t.Errorf("roleId: got %v", got)
	}
	if got := rs.createdInput["role"]; got != "ReadOnly" {
		t.Errorf("role: got %v, want ReadOnly", got)
	}
}

func TestRequest_AllFlagsRejectUnknownAccount(t *testing.T) {
	home := t.TempDir()
	rs := newRequestServer(t, "123456789012", "Production",
		"arn:aws:sso:::permissionSet/ssoins/ps-abc", "ReadOnly")
	env := setupRequestEnv(t, home, rs.srv.URL, "test-client", "us-east-1_pool")

	_, stderr, code := runBinEnv(env,
		"request",
		"--account", "UnknownAcct",
		"--role", "ReadOnly",
		"--duration", "4",
		"--justification", "x",
		"--yes",
	)
	if code == 0 {
		t.Fatal("expected non-zero exit for unknown account")
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("expected 'not found' in stderr, got: %s", stderr)
	}
}

func TestRequest_PolicyFetched_WhenAllFlagsProvided(t *testing.T) {
	home := t.TempDir()
	rs := newRequestServer(t, "123456789012", "Production",
		"arn:aws:sso:::permissionSet/ssoins/ps-abc", "ReadOnly")
	env := setupRequestEnv(t, home, rs.srv.URL, "test-client", "us-east-1_pool")

	_, stderr, code := runBinEnv(env,
		"request",
		"--account", "Production",
		"--role", "ReadOnly",
		"--duration", "4",
		"--justification", "x",
		"--yes",
	)
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	if !rs.sawOperation("GetUserPolicy") {
		t.Error("expected getUserPolicy operation to be invoked even when all flags are provided")
	}
}


func TestRequestDirectFallback_FlagsCompleteSkipsRealtime(t *testing.T) {
	home := t.TempDir()
	rs := newDirectGrantServer(t)
	env := setupRequestEnv(t, home, rs.srv.URL, "test-client", "us-east-1_pool")

	stdout, stderr, code := runBinEnvInput(env, "\n",
		"request",
		"--account", "123456789012",
		"--role", "arn:aws:sso:::permissionSet/ssoins/ps-abc",
		"--duration", "4",
		"--justification", "x",
		"--yes",
	)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "entitlement autodiscovery") {
		t.Fatalf("expected realtime to be skipped when flags complete, got stderr: %s", stderr)
	}
}
