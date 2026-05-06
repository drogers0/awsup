# Title
Direct-Grant Entitlement Autodiscovery via AppSync Realtime Fallback

## Problem Summary

`getUserPolicy` returns `policy: null` for direct-grant IAM Identity Center users. The original CLI immediately prompted for an account ID and permission set ARN, making it unusable without out-of-band knowledge of those values. The browser app discovers entitlements via three channels: (1) `getUserPolicy` for group-policy users, (2) `getMgmtPermissions` for known permission-set ARNs, and (3) an `onPublishPolicy` realtime WebSocket subscription that delivers `(account, permission set)` pairs with display names. This plan adds the same realtime discovery path to the CLI and introduces an `options` subcommand for non-interactive enumeration.

## Design Decisions

### 1. AppSync realtime authentication uses the access token in `Sec-WebSocket-Protocol`, not the ID token in `connection_init`

AppSync's realtime channel rejects the ID token. Auth must be the Cognito **access token** (`token_use: access`) encoded as a base64 JSON object in a `header-<b64>` subprotocol string:

```
Sec-WebSocket-Protocol: graphql-ws, header-<base64({"Authorization":"<access-token>","host":"<realtime-host>"})>
```

The `connection_init` frame carries no payload. The subscription `start` frame carries a redundant `extensions.authorization` object (access token + host + user-agent) as AppSync requires both for the start message.

**Considered:** putting auth in URL query params (what some AppSync examples show for API-key auth). **Rejected:** Cognito user pool auth exclusively uses the header subprotocol pattern.

**Considered:** using the ID token with `Bearer` prefix. **Rejected:** AppSync rejects it with `connection_error: unauthorized` — only the access token works for WebSocket.

### 2. `onPublishPolicy` takes no arguments; auth identity drives filtering server-side

The subscription has no `$userId`/`$groupIds` parameters. The server returns entitlements for the identity embedded in the access token. Passing variables causes a schema error.

**Considered:** forwarding userId/groupIds as in the original plan. **Rejected:** schema introspection confirmed no arguments exist.

### 3. The realtime payload is `[Entitlement]`, not a flat `{accounts, permissions}`

Each `Entitlement` object typically represents one `(account, permission set)` pair. The client must flatten and deduplicate across the list to produce usable account and permission set dropdowns.

```go
type realtimeEntitlement struct {
    Accounts    []Account    `json:"accounts"`
    Permissions []Permission `json:"permissions"`
    // ...
}
type realtimePolicy struct {
    Policy []realtimeEntitlement `json:"policy"`
}
```

### 4. One `SetReadDeadline` call, not a polling loop

gorilla/websocket v1.5.x marks the connection permanently failed after any read error, including a timeout. Subsequent `ReadJSON` calls panic. The fix: set `SetReadDeadline` once to the context's deadline before the blocking `ReadJSON` call — no retries, no loops around the read.

**Considered:** goroutine-select pattern (spawn goroutine for read, select on goroutine channel + `ctx.Done()`). **Not chosen:** adds goroutine lifecycle complexity with no practical benefit given we only need one message. Current approach is simpler and correct.

### 5. Skip realtime only when both flags are already raw IDs

`--account 343084147688 --role arn:aws:sso:::...` means both values are fully resolved; realtime lookup adds no value. The heuristic: 12-digit numeric accountID and ARN-prefixed roleID.

**Considered:** skipping realtime whenever both flags are non-empty. **Rejected:** display names like `--account VU-Research-ISIS-ScopeLab --role VU_PowerUserAccess` require realtime to resolve to IDs and names. The old `accountID == "" || roleID == ""` condition missed this case.

### 6. Access token is persisted in the token cache

The access token is stored alongside the ID token in `tokencache.Cache` and refreshed together. Without this, the CLI would have no access token for WebSocket auth after the initial session.

**Considered:** re-fetching the access token on demand from Cognito. **Rejected:** requires the refresh token and a round-trip; caching is simpler and consistent with how the ID token is handled.

### 7. `getRealtimeEntitlements` as an injectable function variable for testing

Tests replace `getRealtimeEntitlements` to avoid live WebSocket connections in main-package tests. The policy-package tests use a fake dialer (`wsDialContext`) for the same reason.

### 8. `newAuthenticatedClient` helper deduplicates client construction

All four subcommands (`request`, `options`, `list`, `settings`) construct an `appsync.Client` with the same three lines: `appsync.New(...)` + conditional `SetAccessToken`. Extracted into `newAuthenticatedClient(cfg, tokens)`.

### 9. `resolveDirectGrantFromRealtime` retains an internal `looksLikeRawIDs` guard as defensive programming

The outer call site in `runRequest` already guards with `!looksLikeRawIDs(accountID, roleID)`, making the function-internal guard redundant in production. It is retained with a comment so that the function is safe and efficient when called standalone (e.g., directly in tests) without assuming the caller applied the guard.

### 10. `isUnauthorizedErr` helper removed; error handling uses inline `errors.As` in a switch

The helper was called exactly once. Inline error-type switching is clearer and avoids premature abstraction.

### 11. `options` subcommand for agent-friendly non-interactive enumeration

Agents and scripts cannot interact with `--account`/`--role` selection prompts. `awsup options --json` returns the full resolved account and permission set list (IDs + display names) via realtime, enabling callers to fill in all `request` flags programmatically.

### 9. Realtime failures in `runRequest` are non-fatal

Timeout → falls back to manual prompt with an info message. Authorization failure or network error → falls back silently (debug message). The request flow is never blocked by realtime discovery failure.

## Implementation

### 1. `internal/tokencache/cache.go` — persist access token

- Add `AccessToken string \`json:"accessToken,omitempty"\`` to `Cache`.
- `Refresh()`: populate `newCache.AccessToken` from the token endpoint response.
- `GetValid()` / browser fallback: populate `fresh.AccessToken` from `tokens.AccessToken`.

### 2. `internal/appsync/client.go` — access token support

- Add `accessToken string` field to `Client`.
- Add `SetAccessToken(t string)` setter.
- Add `UserAgent() string` getter.
- Add `RealtimeToken() string` — returns access token if set, falls back to ID token.

### 3. `internal/policy/policy.go` — realtime subscription

- Add dependency: `github.com/gorilla/websocket`.
- Add types: `realtimeEntitlement`, `realtimePolicy`, `onPublishDataFrame`, `wsMessage`, `subscriptionExtensions`, `subscriptionStartPayload`, `subscriptionRequest`, `connectionErrorFrame`.
- Add package-level `wsDialContext` function variable (injectable for tests):
  ```go
  var wsDialContext = func(ctx context.Context, wsURL string, subprotocols []string) (*websocket.Conn, *http.Response, error) {
      dialer := websocket.Dialer{Subprotocols: subprotocols}
      return dialer.DialContext(ctx, wsURL, nil)
  }
  ```
- Add `deriveRealtimeEndpoint(endpoint, token string) (wsURL, apiHost string, subprotocols []string, err error)` — transforms HTTPS AppSync URL to WSS realtime URL and builds auth subprotocols.
- Add `flattenEntitlements([]realtimeEntitlement) *Policy` — deduplicates accounts and permissions across entitlement list.
- Add `readWSMessage(ctx, conn) (wsMessage, error)` — sets `SetReadDeadline` to context deadline once, then reads one frame. Returns `context.DeadlineExceeded` when the deadline has passed (handles the gorilla panic-avoidance requirement).
- Add `sendComplete(conn, id)` helper.
- Add `writeWSJSON(conn, v) error` helper.
- Add `GetOnPublishPolicyEntitlements(ctx, client, userID, groupIDs) (*Policy, error)`:
  - Derives WSS URL and subprotocols from client endpoint + realtime token.
  - Dials with subprotocols (auth in header).
  - Sends `connection_init` (no payload).
  - Waits for `connection_ack`; returns `UnauthorizedError` on `connection_error`.
  - Sends `start` with subscription document + extensions authorization.
  - Reads frames until a usable `data` frame or context expires.
  - Returns first payload where `len(accounts) > 0 || len(permissions) > 0`; partial payloads are valid.
  - Sends `complete` before returning on success.
- Add `GetMgmtPermissions(ctx, client) ([]Permission, error)`.

### 4. `main.go` — direct-grant branch and `options` subcommand

- Set `AccessToken` on every new `appsync.Client` when the token cache has one.
- Add `realtimeEntitlementTimeout = 7 * time.Second` constant.
- Add `getRealtimeEntitlements` package-level variable (wraps `policy.GetOnPublishPolicyEntitlements`, injectable for tests).
- Add `looksLikeRawIDs(accountID, roleID string) bool` — true iff accountID is 12-digit numeric and roleID starts with `arn:`.
- Add `applyRealtimeDirectGrantChoices(accountID, roleID string, ent *policy.Policy) (string, string, string, string)` — applies entitlements to flags, selecting interactively for empty values.
- Add `resolveDirectGrantFromRealtime(ctx, client, userID, groupIDs, accountID, roleID) (string, string, string, string, error)` — calls `getRealtimeEntitlements` and applies choices. Callers should guard with `looksLikeRawIDs` to skip the call when flags are already resolved.
- In `runRequest` direct-grant branch: call `resolveDirectGrantFromRealtime` when `!looksLikeRawIDs(accountID, roleID)`. On success, use resolved values; on failure, log and fall through to manual prompts.
- After realtime resolution, fall through to `getMgmtPermissions` for roleID resolution when roleID is still unresolved or has no display name.
- Add `runOptions` — fetches group policy or realtime entitlements, prints accounts and permissions; supports `--json`.
- Add `options` to the command switch and usage string.

### 5. Tests

**`internal/policy/policy_test.go`:**
- Replace `withTestDialer` to inject a fake dialer via `wsDialContext`.
- `newRealtimeServer` helper that upgrades HTTP to WebSocket and calls a handler.
- `realtimeClient()` helper with a valid AppSync-format endpoint.
- Tests: success, partial (accounts only), partial (permissions only), empty-then-usable, timeout (`context.DeadlineExceeded`), unauthorized (`connection_error`), subscription error, complete-without-data, malformed payload, invalid endpoint.

**`main_test.go`:**
- `TestResolveDirectGrantFromRealtime_SkipsWhenFlagsComplete` — verifies `looksLikeRawIDs` guard: 12-digit account + ARN role → realtime not called.
- `TestResolveDirectGrantFromRealtime_PartialResult` — realtime returns account only; roleID/roleName remain empty.
- `TestResolveDirectGrantFromRealtime_TimeoutError` — realtime error is propagated.

## Testing Plan

1. `go test ./...` — all packages must pass.
2. Manual smoke: `awsup options --json` for direct-grant user confirms account list and permission sets with names.
3. Manual smoke: `awsup request --account <name> --role <name> --duration 2 --justification "..."` resolves display names via realtime and submits successfully.
4. Manual smoke: `awsup request --account <12-digit-id> --role <arn> --duration 2 --justification "..." --yes` skips realtime entirely (fast path).

## Rollout and Risk Controls

- Realtime failures are non-fatal in `runRequest` — timeout falls back with an info message; other failures fall back silently with a debug message. The flow always completes.
- Timeout is bounded at 7 seconds to avoid perceived hangs.
- Token values are never logged.
- `validateRequest` remains mandatory before `createRequests` regardless of how entitlements were discovered.

## Reviewer Iteration Log

- Round 1: Two independent reviewers. Applied: renamed `idToken` → `token` in `deriveRealtimeEndpoint`; added `newAuthenticatedClient` helper eliminating 4-way boilerplate; removed single-use `isUnauthorizedErr` helper and inlined `errors.As` switch; added `TestLooksLikeRawIDs` table test; restored inner `looksLikeRawIDs` guard with documenting comment (defensive, not dead code); updated plan with design decisions 8–11.
- Round 2: Two reviewers. Applied: fixed `runOptions` permission merge from wholesale replacement to ID-keyed merge (realtime enriches mgmt names, mgmt-only and realtime-only entries both preserved); standardized all fallback stderr messages to "Debug:" prefix (removed inconsistent "Info:" on timeout).
