package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/drogers0/awsup/internal/appsync"
	"github.com/drogers0/awsup/internal/auth"
	"github.com/drogers0/awsup/internal/config"
	"github.com/drogers0/awsup/internal/policy"
	"github.com/drogers0/awsup/internal/settings"
	"github.com/drogers0/awsup/internal/tokencache"
)

// version is overridden at release time via goreleaser ldflags:
//
// -X main.version={{.Version}}
var version = "dev"

const realtimeEntitlementTimeout = 7 * time.Second

const usage = `Usage:
  awsup [--profile <name>] <command> [flags]

Commands:
  init      Auto-discover config from your browser session
  request   Submit an elevated-access request
  options   List available accounts and permission sets
  list      List your requests
  settings  Show deployment settings
  profile   Manage profiles

Run 'awsup <command> --help' for command-specific flags.`

// requestRecord is a TEAM access request as returned by AppSync.
type requestRecord struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	AccountID       string  `json:"accountId"`
	AccountName     string  `json:"accountName"`
	Role            string  `json:"role"`
	RoleID          string  `json:"roleId"`
	StartTime       string  `json:"startTime"`
	Duration        string  `json:"duration"`
	Justification   string  `json:"justification"`
	Status          string  `json:"status"`
	Comment         string  `json:"comment"`
	Username        string  `json:"username"`
	Approver        string  `json:"approver"`
	ApproverID      string  `json:"approverId"`
	Approvers       *string `json:"approvers"`
	ApproverIDs     *string `json:"approver_ids"`
	Revoker         string  `json:"revoker"`
	RevokerID       string  `json:"revokerId"`
	EndTime         string  `json:"endTime"`
	TicketNo        string  `json:"ticketNo"`
	RevokeComment   string  `json:"revokeComment"`
	SessionDuration string  `json:"session_duration"`
	CreatedAt       string  `json:"createdAt"`
	UpdatedAt       string  `json:"updatedAt"`
	Owner           string  `json:"owner"`
	Typename        string  `json:"__typename"`
}

// ---- GraphQL constants ----

const validateRequestMutation = `
mutation ValidateRequest($accountId: String!, $roleId: String!, $userId: String!, $groupIds: [String]!) {
  validateRequest(accountId: $accountId, roleId: $roleId, userId: $userId, groupIds: $groupIds) {
    valid
    reason
  }
}`

const createRequestsMutation = `
mutation CreateRequests($input: CreateRequestsInput!, $condition: ModelRequestsConditionInput) {
  createRequests(input: $input, condition: $condition) {
    id email accountId accountName role roleId
    startTime duration justification status comment
    username approver approverId approvers approver_ids
    revoker revokerId endTime ticketNo revokeComment
    session_duration createdAt updatedAt owner __typename
  }
}`

const listRequestsQuery = `
query RequestByEmailAndStatus($email: String!, $status: ModelStringKeyConditionInput, $sortDirection: ModelSortDirection, $filter: ModelrequestsFilterInput, $limit: Int, $nextToken: String) {
  requestByEmailAndStatus(email: $email, status: $status, sortDirection: $sortDirection, filter: $filter, limit: $limit, nextToken: $nextToken) {
    items {
      id email accountId accountName role roleId
      startTime duration justification status comment
      username approver approverId approvers approver_ids
      revoker revokerId endTime ticketNo revokeComment
      session_duration createdAt updatedAt owner __typename
    }
    nextToken
    __typename
  }
}`

// ---- GraphQL variable/response types ----

type validateRequestVars struct {
	AccountID string   `json:"accountId"`
	RoleID    string   `json:"roleId"`
	UserID    string   `json:"userId"`
	GroupIDs  []string `json:"groupIds"`
}

type validateRequestResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

type validateRequestData struct {
	ValidateRequest *validateRequestResult `json:"validateRequest"`
}

type createRequestsInput struct {
	AccountID     string `json:"accountId"`
	AccountName   string `json:"accountName"`
	Role          string `json:"role"`
	RoleID        string `json:"roleId"`
	Duration      string `json:"duration"`
	StartTime     string `json:"startTime"`
	Justification string `json:"justification"`
	TicketNo      string `json:"ticketNo"`
}

type createRequestsVars struct {
	Input     createRequestsInput `json:"input"`
	Condition *struct{}           `json:"condition,omitempty"`
}

type createRequestsData struct {
	CreateRequests *requestRecord `json:"createRequests"`
}

type listRequestsVars struct {
	Email     string  `json:"email"`
	NextToken *string `json:"nextToken"`
}

type listRequestsPage struct {
	Items     []requestRecord `json:"items"`
	NextToken *string         `json:"nextToken"`
}

type listRequestsData struct {
	RequestByEmailAndStatus listRequestsPage `json:"requestByEmailAndStatus"`
}

// ---- helpers ----

func mustLoadConfig(profile string) *config.Config {
	cfg, err := config.Load(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n  → run 'awsup init' to auto-discover config from your browser\n", err)
		os.Exit(1)
	}
	return cfg
}

func mustGetTokens(cfg *config.Config) *tokencache.Cache {
	cache, err := tokencache.GetValid(cfg.CachePath(), cfg.AppClientID, cfg.UserPoolID, cfg.HostedUIDomain)
	if err != nil {
		if errors.Is(err, auth.ErrNoSession) || errors.Is(err, tokencache.ErrSessionExpired) {
			fmt.Fprintln(os.Stderr, "Error: "+err.Error())
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "Error: auth failed: %v\n", err)
		os.Exit(3)
	}
	return cache
}

func checkTransportErr(err error) {
	if err == nil {
		return
	}
	var unauth *appsync.UnauthorizedError
	if errors.As(err, &unauth) {
		fmt.Fprintf(os.Stderr, "Error: unauthorized — %v\n", unauth)
		os.Exit(3)
	}
	var netErr *appsync.NetworkError
	if errors.As(err, &netErr) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", netErr)
		os.Exit(4)
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

// stdinReader is shared across all prompt calls. A per-call bufio.Reader
// would over-read the pipe and discard buffered bytes belonging to the next
// prompt — fatal for piped multi-line input.
// Tests replace this; callers must not use t.Parallel() — package-level mutation.
var stdinReader = bufio.NewReader(os.Stdin)

// getRealtimeEntitlements is replaceable in tests to avoid live realtime connections.
// Tests replace this; callers must not use t.Parallel() — package-level mutation.
var getRealtimeEntitlements = policy.GetOnPublishPolicyEntitlements

// promptLine reads a line from stdin and reports whether stdin was open.
// Returns ("", false) on EOF / closed stdin so callers can distinguish that
// from a user pressing Enter on an empty line.
func promptLine(msg string) (string, bool) {
	fmt.Print(msg)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return strings.TrimSpace(line), true
}

// mustPromptLine reads a required input from stdin. EOF / closed stdin is
// fatal — empty stdin pipelines that need this prompt cannot proceed
// meaningfully.
func mustPromptLine(msg string) string {
	line, ok := promptLine(msg)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: stdin closed")
		os.Exit(1)
	}
	return line
}

func parseSubcmdFlags(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "Error: writing output: %v\n", err)
		os.Exit(1)
	}
}

func resolveByIDOrName[T any](items []T, input string, key func(T) (id, name string)) (id, name string, ok bool) {
	for _, it := range items {
		id, name = key(it)
		if id == input || strings.EqualFold(name, input) {
			return id, name, true
		}
	}
	return "", "", false
}

func selectFromList[T any](label string, items []T, key func(T) (id, name string)) (id, name string) {
	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no %s available in your policy\n", label)
		os.Exit(1)
	}
	render := func(t T) string {
		id, name := key(t)
		if name == "" || name == id {
			return id
		}
		return name + " (" + id + ")"
	}
	if len(items) == 1 {
		id, name = key(items[0])
		fmt.Printf("Auto-selected %s: %s\n", label, render(items[0]))
		return id, name
	}
	fmt.Printf("Available %s:\n", label)
	for i, it := range items {
		fmt.Printf("  %d. %s\n", i+1, render(it))
	}
	for {
		sel := mustPromptLine(fmt.Sprintf("Select %s [1-%d]: ", label, len(items)))
		n, err := strconv.Atoi(sel)
		if err != nil || n < 1 || n > len(items) {
			fmt.Fprintf(os.Stderr, "Invalid selection, enter a number 1–%d\n", len(items))
			continue
		}
		return key(items[n-1])
	}
}

func formatChoices[T any](items []T, key func(T) (id, name string)) string {
	parts := make([]string, len(items))
	for i, it := range items {
		id, name := key(it)
		parts[i] = name + " (" + id + ")"
	}
	return strings.Join(parts, ", ")
}

func newAuthenticatedClient(cfg *config.Config, tokens *tokencache.Cache) *appsync.Client {
	c := appsync.New(cfg.AppSyncEndpoint, cfg.FrontendURL, cfg.AmplifyUserAgent, tokens.IDToken)
	if tokens.AccessToken != "" {
		c.SetAccessToken(tokens.AccessToken)
	}
	return c
}

func accountKey(a policy.Account) (string, string)       { return a.ID, a.Name }
func permissionKey(p policy.Permission) (string, string) { return p.ID, p.Name }

func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func applyRealtimeDirectGrantChoices(accountID, roleID string, ent *policy.Policy) (string, string, string, string) {
	if ent == nil {
		return accountID, "", roleID, ""
	}
	var accountName, roleName string
	if len(ent.Accounts) > 0 {
		if accountID == "" {
			accountID, accountName = selectFromList("accounts", ent.Accounts, accountKey)
		} else if id, name, ok := resolveByIDOrName(ent.Accounts, accountID, accountKey); ok {
			accountID, accountName = id, name
		}
	}
	if len(ent.Permissions) > 0 {
		if roleID == "" {
			roleID, roleName = selectFromList("permission sets", ent.Permissions, permissionKey)
		} else if id, name, ok := resolveByIDOrName(ent.Permissions, roleID, permissionKey); ok {
			roleID, roleName = id, name
		}
	}
	return accountID, accountName, roleID, roleName
}

// looksLikeRawIDs returns true when accountID is a 12-digit AWS account number
// and roleID starts with "arn:", meaning both are already resolved and realtime
// lookup can be skipped.
func looksLikeRawIDs(accountID, roleID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, c := range accountID {
		if c < '0' || c > '9' {
			return false
		}
	}
	return strings.HasPrefix(roleID, "arn:")
}

type realtimeResult struct {
	policy *policy.Policy
	err    error
}

// startRealtimeSubscription launches GetOnPublishPolicyEntitlements in a
// background goroutine using rtCtx (which the caller must cancel when done).
// The returned channel is buffered (size 1) so the goroutine never blocks on
// send, even if the caller cancels without consuming the result.
func startRealtimeSubscription(rtCtx context.Context, client *appsync.Client, userID string, groupIDs []string) <-chan realtimeResult {
	ch := make(chan realtimeResult, 1)
	go func() {
		p, err := getRealtimeEntitlements(rtCtx, client, userID, groupIDs)
		ch <- realtimeResult{policy: p, err: err}
	}()
	return ch
}

// Sentinel errors returned by requestOrchestrator. The wrapper inspects these
// to map back to today's exit codes (0 for cancel, 2 for invalid request) and
// to suppress double-printing — the orchestrator itself prints the
// user-visible message before returning a sentinel.
var (
	errUserCancelled   = errors.New("user cancelled at confirmation")
	errRequestNotValid = errors.New("request rejected by validateRequest")
)

// exitCodeFor maps an orchestrator return error to the process exit code,
// preserving today's checkTransportErr semantics (3=unauthorized, 4=network,
// 2=invalid request, 0=cancelled, 1=everything else).
func exitCodeFor(err error) int {
	switch {
	case err == nil, errors.Is(err, errUserCancelled):
		return 0
	case errors.Is(err, errRequestNotValid):
		return 2
	}
	var unauth *appsync.UnauthorizedError
	if errors.As(err, &unauth) {
		return 3
	}
	var netErr *appsync.NetworkError
	if errors.As(err, &netErr) {
		return 4
	}
	return 1
}

// ---- subcommands ----

type requestFlags struct {
	accountFlag       string
	roleFlag          string
	durationFlag      string
	justificationFlag string
	ticketFlag        string
	startFlag         string
	yes               bool
	jsonOut           bool
}

func runRequest(profile string, args []string) {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	var (
		accountFlag       = fs.String("account", "", "AWS account ID or display name")
		roleFlag          = fs.String("role", "", "Permission set name or ARN")
		durationFlag      = fs.String("duration", "", "Duration in hours")
		justificationFlag = fs.String("justification", "", "Business reason")
		ticketFlag        = fs.String("ticket", "", "Ticket reference")
		startFlag         = fs.String("start", "", "Start time ISO 8601 (default: now)")
		yes               = fs.Bool("yes", false, "Skip confirmation prompt")
		jsonOut           = fs.Bool("json", false, "Output created request as JSON")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: awsup request [flags]

Flags:
  --account <id|name>       AWS account ID or display name
  --role <name|arn>         Permission set name or ARN
  --duration <hours>        Duration in hours
  --justification <text>    Business reason
  --ticket <ref>            Ticket reference
  --start <iso8601>         Start time (default: now)
  --yes                     Skip confirmation
  --json                    Output JSON`)
	}
	parseSubcmdFlags(fs, args)

	cfg := mustLoadConfig(profile)
	tokens := mustGetTokens(cfg)
	flags := requestFlags{
		accountFlag:       *accountFlag,
		roleFlag:          *roleFlag,
		durationFlag:      *durationFlag,
		justificationFlag: *justificationFlag,
		ticketFlag:        *ticketFlag,
		startFlag:         *startFlag,
		yes:               *yes,
		jsonOut:           *jsonOut,
	}
	err := requestOrchestrator(context.Background(), cfg, tokens, flags)

	// Print branches mirror today's checkTransportErr formats (main.go:193, 198, 201).
	// Sentinel errors print inside the orchestrator and must NOT be re-printed here.
	var unauth *appsync.UnauthorizedError
	var netErr *appsync.NetworkError
	switch {
	case err == nil,
		errors.Is(err, errUserCancelled),
		errors.Is(err, errRequestNotValid):
		// already printed (or no error)
	case errors.As(err, &unauth):
		fmt.Fprintf(os.Stderr, "Error: unauthorized — %v\n", unauth)
	case errors.As(err, &netErr):
		fmt.Fprintf(os.Stderr, "Error: %v\n", netErr)
	default:
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(exitCodeFor(err))
}

// requestOrchestrator runs the body of `awsup request` and returns errors
// instead of calling os.Exit, so tests can drive it directly. The wrapper
// (runRequest) maps the returned error to a process exit code via exitCodeFor.
func requestOrchestrator(ctx context.Context, cfg *config.Config, tokens *tokencache.Cache, flags requestFlags) error {
	client := newAuthenticatedClient(cfg, tokens)

	sett, err := settings.Get(ctx, client)
	if err != nil {
		return err
	}

	accountID := flags.accountFlag
	roleID := flags.roleFlag
	var accountName, roleName string
	durationStr := flags.durationFlag
	justification := flags.justificationFlag

	// Launch the realtime WebSocket subscription concurrently with policy.Get
	// so the WS is subscribed before the backend's onPublishPolicy push fires
	// (~900ms after getUserPolicy). Group-policy users will land on the cancel
	// branch below; the WS dial is aborted within milliseconds. When both flags
	// are raw IDs, we know up-front realtime is not needed and skip the launch.
	rtCtx, rtCancel := context.WithTimeout(ctx, realtimeEntitlementTimeout)
	defer rtCancel()
	var rtCh <-chan realtimeResult
	if !looksLikeRawIDs(accountID, roleID) {
		rtCh = startRealtimeSubscription(rtCtx, client, tokens.UserID, tokens.GroupIDs)
	}

	up, err := policy.Get(ctx, client, tokens.UserID, tokens.GroupIDs)
	if err != nil {
		return err
	}

	if up.Policy == nil {
		// Direct-grant user: no group-based policy.
		if rtCh != nil {
			rt := <-rtCh
			if rt.err != nil {
				var unauth *appsync.UnauthorizedError
				switch {
				case errors.Is(rt.err, context.DeadlineExceeded):
					fmt.Fprintln(os.Stderr, "Debug: entitlement autodiscovery timed out, using manual fallback")
				case errors.As(rt.err, &unauth):
					fmt.Fprintf(os.Stderr, "Debug: entitlement autodiscovery unauthorized, using manual fallback: %v\n", rt.err)
				default:
					fmt.Fprintf(os.Stderr, "Debug: entitlement autodiscovery failed, using manual fallback: %v\n", rt.err)
				}
			} else {
				accountID, accountName, roleID, roleName = applyRealtimeDirectGrantChoices(accountID, roleID, rt.policy)
			}
		}

		if accountID == "" {
			accountID = mustPromptLine("Enter AWS account ID: ")
		}
		if accountName == "" {
			label := mustPromptLine(fmt.Sprintf("Account display name [%s]: ", accountID))
			if label == "" {
				accountName = accountID
			} else {
				accountName = label
			}
		}

		if roleID == "" {
			roleID = mustPromptLine("Enter permission set ARN: ")
			roleName = roleID
		} else if roleName == "" {
			roleName = roleID
		}
	} else {
		rtCancel() // group-policy user; cancel the (possibly running) subscription
		if accountID == "" {
			accountID, accountName = selectFromList("accounts", up.Policy.Accounts, accountKey)
		} else {
			id, name, ok := resolveByIDOrName(up.Policy.Accounts, accountID, accountKey)
			if !ok {
				return fmt.Errorf("account %q not found in your policy. Available: %s",
					accountID, formatChoices(up.Policy.Accounts, accountKey))
			}
			accountID, accountName = id, name
		}
		if roleID == "" {
			roleID, roleName = selectFromList("permission sets", up.Policy.Permissions, permissionKey)
		} else {
			id, name, ok := resolveByIDOrName(up.Policy.Permissions, roleID, permissionKey)
			if !ok {
				return fmt.Errorf("role %q not found in your policy. Available: %s",
					roleID, formatChoices(up.Policy.Permissions, permissionKey))
			}
			roleID, roleName = id, name
		}
	}

	if durationStr == "" {
		maxDurLabel := sett.Duration
		if maxDurLabel == "" {
			maxDurLabel = "8"
		}
		for {
			durationStr = mustPromptLine(fmt.Sprintf("Duration in hours [1-%s]: ", maxDurLabel))
			if _, parseErr := strconv.Atoi(durationStr); parseErr == nil {
				break
			}
			fmt.Fprintln(os.Stderr, "Enter a whole number of hours")
		}
	}

	if justification == "" {
		justification = mustPromptLine("Justification: ")
		if justification == "" {
			return fmt.Errorf("justification is required")
		}
	}

	reqDur, err := strconv.Atoi(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration %q: must be a whole number", durationStr)
	}
	if sett.Duration != "" {
		maxDur, parseErr := strconv.Atoi(sett.Duration)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: server returned non-numeric max duration %q; skipping enforcement\n", sett.Duration)
		} else if maxDur > 0 && reqDur > maxDur {
			return fmt.Errorf("requested duration %d hours exceeds maximum %d hours", reqDur, maxDur)
		}
	}

	ticket := flags.ticketFlag
	if sett.TicketNo && ticket == "" {
		ticket = mustPromptLine("Ticket number: ")
		if ticket == "" {
			return fmt.Errorf("ticket number is required")
		}
	}

	startTime := flags.startFlag
	if startTime == "" {
		startTime = time.Now().Format(time.RFC3339)
	}

	vData, err := appsync.Execute[validateRequestData](ctx, client, validateRequestMutation, validateRequestVars{
		AccountID: accountID,
		RoleID:    roleID,
		UserID:    tokens.UserID,
		GroupIDs:  tokens.GroupIDs,
	})
	if err != nil {
		return err
	}
	if vData.ValidateRequest != nil && !vData.ValidateRequest.Valid {
		fmt.Fprintf(os.Stderr, "Error: request not valid: %s\n", vData.ValidateRequest.Reason)
		return errRequestNotValid
	}

	if !flags.yes {
		fmt.Printf("\nRequest summary:\n")
		fmt.Printf("  Account:       %s (%s)\n", accountName, accountID)
		fmt.Printf("  Role:          %s\n", roleName)
		fmt.Printf("  Duration:      %s hours\n", durationStr)
		fmt.Printf("  Start:         %s\n", startTime)
		fmt.Printf("  Justification: %s\n", justification)
		if ticket != "" {
			fmt.Printf("  Ticket:        %s\n", ticket)
		}
		answer, ok := promptLine("\nSubmit? [y/N] ")
		if !ok || (!strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes")) {
			fmt.Println("Cancelled.")
			return errUserCancelled
		}
	}

	cData, err := appsync.Execute[createRequestsData](ctx, client, createRequestsMutation, createRequestsVars{
		Input: createRequestsInput{
			AccountID:     accountID,
			AccountName:   accountName,
			Role:          roleName,
			RoleID:        roleID,
			Duration:      durationStr,
			StartTime:     startTime,
			Justification: justification,
			TicketNo:      ticket,
		},
	})
	if err != nil {
		return err
	}

	rec := cData.CreateRequests
	if rec == nil {
		return fmt.Errorf("createRequests returned null")
	}

	if flags.jsonOut {
		printJSON(rec)
		return nil
	}
	fmt.Printf("Request %s submitted — status: %s\n", rec.ID, rec.Status)
	fmt.Printf("View requests: %s/requests\n", cfg.FrontendURL)
	return nil
}

type optionsResult struct {
	PolicyType  string              `json:"policy_type"`
	Accounts    []policy.Account    `json:"accounts"`
	Permissions []policy.Permission `json:"permissions"`
}

func runOptions(profile string, args []string) {
	fs := flag.NewFlagSet("options", flag.ContinueOnError)
	var jsonOut = fs.Bool("json", false, "Output JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: awsup options [flags]

Show accounts and permission sets available for 'awsup request'.

Flags:
  --json   Output JSON`)
	}
	parseSubcmdFlags(fs, args)

	cfg := mustLoadConfig(profile)
	tokens := mustGetTokens(cfg)
	ctx := context.Background()
	client := newAuthenticatedClient(cfg, tokens)

	// Launch realtime concurrently with policy.Get (see runRequest comment).
	// runOptions has no flags to short-circuit on, so it always launches.
	rtCtx, rtCancel := context.WithTimeout(ctx, realtimeEntitlementTimeout)
	defer rtCancel()
	rtCh := startRealtimeSubscription(rtCtx, client, tokens.UserID, tokens.GroupIDs)

	up, err := policy.Get(ctx, client, tokens.UserID, tokens.GroupIDs)
	checkTransportErr(err)

	result := optionsResult{
		Accounts:    []policy.Account{},
		Permissions: []policy.Permission{},
	}

	if up.Policy != nil {
		rtCancel()
		result.PolicyType = "group_policy"
		result.Accounts = up.Policy.Accounts
		result.Permissions = up.Policy.Permissions
	} else {
		result.PolicyType = "direct_grant"
		rt := <-rtCh
		if rt.err != nil {
			fmt.Fprintf(os.Stderr, "Debug: realtime entitlements: %v\n", rt.err)
		} else if rt.policy != nil {
			result.Accounts = rt.policy.Accounts
			result.Permissions = rt.policy.Permissions
		}
	}

	if *jsonOut {
		printJSON(result)
		return
	}

	fmt.Printf("Policy type: %s\n\n", result.PolicyType)
	if len(result.Accounts) == 0 {
		fmt.Println("Accounts: (not discoverable — provide --account <id> to request)")
	} else {
		fmt.Println("Accounts:")
		for _, a := range result.Accounts {
			if a.Name != "" && a.Name != a.ID {
				fmt.Printf("  %s (%s)\n", a.Name, a.ID)
			} else {
				fmt.Printf("  %s\n", a.ID)
			}
		}
	}
	fmt.Println()
	if len(result.Permissions) == 0 {
		fmt.Println("Permission sets: (none found)")
	} else {
		fmt.Println("Permission sets:")
		for _, p := range result.Permissions {
			if p.Name != "" && p.Name != p.ID {
				fmt.Printf("  %s (%s)\n", p.Name, p.ID)
			} else {
				fmt.Printf("  %s\n", p.ID)
			}
		}
	}
}

func runList(profile string, args []string) {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var (
		statusFilter = fs.String("status", "", "Filter by status")
		limit        = fs.Int("limit", 0, "Max records (0 = all)")
		jsonOut      = fs.Bool("json", false, "Output JSON array")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: awsup list [flags]

Flags:
  --status <value>   Filter by status
  --limit N          Max records (default: all)
  --json             Output JSON array`)
	}
	parseSubcmdFlags(fs, args)

	cfg := mustLoadConfig(profile)
	tokens := mustGetTokens(cfg)
	ctx := context.Background()
	client := newAuthenticatedClient(cfg, tokens)

	var all []requestRecord
	var nextToken *string
	for {
		data, err := appsync.Execute[listRequestsData](ctx, client, listRequestsQuery, listRequestsVars{
			Email:     tokens.Email,
			NextToken: nextToken,
		})
		checkTransportErr(err)

		page := data.RequestByEmailAndStatus
		all = append(all, page.Items...)

		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		if *limit > 0 && len(all) >= *limit {
			break
		}
		nextToken = page.NextToken
	}

	if *limit > 0 && len(all) > *limit {
		all = all[:*limit]
	}

	if *statusFilter != "" {
		filtered := all[:0]
		for _, r := range all {
			if strings.EqualFold(r.Status, *statusFilter) {
				filtered = append(filtered, r)
			}
		}
		all = filtered
	}

	if *jsonOut {
		printJSON(all)
		return
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tACCOUNT\tROLE\tSTATUS\tSTART\tDURATION\tAGE")
	for _, r := range all {
		id := r.ID
		if len(id) > 8 {
			id = id[:8]
		}
		startDate := r.StartTime
		if len(startDate) >= 10 {
			startDate = startDate[:10]
		}
		age := ""
		if r.CreatedAt != "" {
			if t, parseErr := time.Parse(time.RFC3339, r.CreatedAt); parseErr == nil {
				age = formatAge(time.Since(t))
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s h\t%s\n",
			id, r.AccountName, r.Role, r.Status, startDate, r.Duration, age)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: writing output: %v\n", err)
		os.Exit(1)
	}
}

func runSettings(profile string, args []string) {
	fs := flag.NewFlagSet("settings", flag.ContinueOnError)
	var jsonOut = fs.Bool("json", false, "Output full settings as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: awsup settings [flags]

Flags:
  --json   Output full settings JSON`)
	}
	parseSubcmdFlags(fs, args)

	cfg := mustLoadConfig(profile)
	tokens := mustGetTokens(cfg)
	ctx := context.Background()
	client := newAuthenticatedClient(cfg, tokens)

	sett, err := settings.Get(ctx, client)
	checkTransportErr(err)

	if *jsonOut {
		printJSON(sett)
		return
	}

	ticketRequired := "not required"
	if sett.TicketNo {
		ticketRequired = "required"
	}
	approvalRequired := "not required"
	if sett.Approval {
		approvalRequired = "required"
	}

	fmt.Printf("Max duration:  %s hours\n", sett.Duration)
	fmt.Printf("Expiry:        %s days\n", sett.Expiry)
	fmt.Printf("Justification: required\n")
	fmt.Printf("Ticket number: %s\n", ticketRequired)
	fmt.Printf("Approval:      %s\n", approvalRequired)
}

func runInit(profile string, args []string) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var (
		yes   = fs.Bool("yes", false, "Skip confirmation and write immediately")
		print = fs.Bool("print", false, "Print discovered config only; do not offer to write")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: awsup init [flags]

Discovers deployment config from your browser session and writes
~/.config/awsup/<profile>.env. Sign into TEAM in Chrome first.

Flags:
  --yes     Skip confirmation prompt and write immediately
  --print   Print discovered config only; do not write`)
	}
	parseSubcmdFlags(fs, args)

	sessions, err := auth.AllSessions()
	if err != nil {
		if errors.Is(err, auth.ErrNoSession) {
			fmt.Fprintln(os.Stderr, "Error: sign into TEAM in your browser first")
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	// Filter out localhost sessions; fall back to all if none remain.
	var candidates []auth.RawSession
	for _, s := range sessions {
		if !strings.HasPrefix(s.FrontendURL, "http://localhost") {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		candidates = sessions
	}

	// If multiple sessions, always prompt for selection (even with --yes).
	chosen := candidates[0]
	if len(candidates) > 1 {
		fmt.Fprintln(os.Stderr, "Multiple TEAM sessions found:")
		for i, s := range candidates {
			fmt.Fprintf(os.Stderr, "  [%d] %s  (client: %s)\n", i+1, s.FrontendURL, s.AppClientID)
		}
		for {
			sel := mustPromptLine(fmt.Sprintf("Select [1-%d]: ", len(candidates)))
			n, selErr := strconv.Atoi(sel)
			if selErr != nil || n < 1 || n > len(candidates) {
				fmt.Fprintf(os.Stderr, "Invalid selection, enter a number 1–%d\n", len(candidates))
				continue
			}
			chosen = candidates[n-1]
			break
		}
	}

	cfg, discoverErr := config.DiscoverFromSession(profile, chosen)
	if cfg == nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", discoverErr)
		os.Exit(1)
	}
	if discoverErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", discoverErr)
	}

	fields := []struct{ key, val string }{
		{"TEAM_COGNITO_APP_CLIENT_ID", cfg.AppClientID},
		{"TEAM_COGNITO_USER_POOL_ID", cfg.UserPoolID},
		{"TEAM_FRONTEND_URL", cfg.FrontendURL},
		{"TEAM_APPSYNC_ENDPOINT", cfg.AppSyncEndpoint},
		{"TEAM_COGNITO_HOSTED_UI_DOMAIN", cfg.HostedUIDomain},
	}

	// Single pass: build the file content (raw values) and print to stdout
	// (with placeholders for empty fields in interactive mode) at once.
	// --print emits the same raw bytes that would be written to the env file.
	const header = "# auto-discovered by awsup init\n"
	var fileContent strings.Builder
	fileContent.WriteString(header)
	fmt.Print(header)
	for _, f := range fields {
		fileContent.WriteString(f.key + "=" + f.val + "\n")
		display := f.val
		if display == "" && !*print {
			display = "<not found — set manually>"
		}
		fmt.Printf("%s=%s\n", f.key, display)
	}

	if *print {
		os.Exit(0)
	}

	target := cfg.EnvFilePath()
	fileExists := false
	if _, statErr := os.Stat(target); statErr == nil {
		fileExists = true
	}

	if !*yes {
		var msg string
		if fileExists {
			msg = fmt.Sprintf("\n%s already exists. Overwrite? [y/N] ", target)
		} else {
			msg = fmt.Sprintf("\nSave to %s? [Y/n] ", target)
		}
		answer, ok := promptLine(msg)
		if !ok {
			fmt.Fprintln(os.Stderr, "Error: stdin closed — pass --yes for non-interactive use")
			os.Exit(1)
		}
		yesAnswer := strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
		defaultYes := !fileExists && answer == ""
		if !yesAnswer && !defaultYes {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}

	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: creating config dir: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(target, []byte(fileContent.String()), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: writing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Saved to %s.\n", target)
}

func runProfile(args []string) {
	if len(args) >= 1 && args[0] == "ls" {
		profiles, err := config.ProfileList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, p := range profiles {
			fmt.Println(p)
		}
		return
	}
	fmt.Fprintln(os.Stderr, `Usage: awsup profile <subcommand>

Subcommands:
  ls   List configured profiles`)
	os.Exit(1)
}

func main() {
	args := os.Args[1:]

	profile := os.Getenv("AWSUP_PROFILE")
	if profile == "" {
		profile = "default"
	}

	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--profile" || arg == "-p":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "Error: --profile requires a value\n%s\n", usage)
				os.Exit(1)
			}
			i++
			profile = args[i]
		case strings.HasPrefix(arg, "--profile="):
			profile = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="):
			profile = strings.SplitN(arg, "=", 2)[1]
		case arg == "--version":
			fmt.Println("awsup " + version)
			os.Exit(0)
		case arg == "--help" || arg == "-h":
			fmt.Println(usage)
			os.Exit(0)
		default:
			rest = append(rest, args[i:]...)
			i = len(args)
		}
	}

	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	subcmd := rest[0]
	subargs := rest[1:]

	switch subcmd {
	case "init":
		runInit(profile, subargs)
	case "request":
		runRequest(profile, subargs)
	case "options":
		runOptions(profile, subargs)
	case "list":
		runList(profile, subargs)
	case "settings":
		runSettings(profile, subargs)
	case "profile":
		runProfile(subargs)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n%s\n", subcmd, usage)
		os.Exit(1)
	}
}
