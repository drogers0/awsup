# Access Request Pitfalls

Observations from walking through `awsup request` as a direct-grant user targeting
`--account scopelab --role poweruser`.

---

## How `awsup request` works end-to-end

Understanding the call sequence makes the pitfalls below easier to reason about.

```
awsup request [flags]
  │
  ├─ 1. Load ~/.config/awsup/<profile>.env
  ├─ 2. GetValid(cachePath) → load or refresh credentials
  │      └─ if cache miss/expired → auth.FromBrowser() → read Chromium LevelDB localStorage
  │
  ├─ 3. getUserPolicy(userId, groupIds)          [HTTP AppSync GraphQL]
  │      ├─ group-policy user  → Policy{ accounts[], permissions[] }
  │      └─ direct-grant user  → Policy = nil
  │
  ├─ 4. (direct-grant only) GetOnPublishPolicyEntitlements()  [AppSync WebSocket]
  │      ├─ success → accounts[] + permissions[] with display names
  │      └─ failure → fall through to manual prompts
  │
  ├─ 5. (direct-grant fallback only) getMgmtPermissions()     [HTTP AppSync GraphQL]
  │      └─ returns []string of permission set ARNs (no display names)
  │
  ├─ 6. Collect account + role + duration + justification (flags or prompts)
  │
  ├─ 7. validateRequest(accountId, roleId, userId, groupIds)  [HTTP AppSync GraphQL]
  │      └─ server checks eligibility; returns { valid, reason }
  │
  ├─ 8. Confirmation prompt (skipped with --yes)
  │
  └─ 9. createRequests(input)                                 [HTTP AppSync GraphQL]
         └─ returns the created request record with id, status, etc.
```

There are two distinct user types with very different flows:
- **Group-policy users** — assigned to an IAM Identity Center group; `getUserPolicy` returns
  a full account + permission-set list; no realtime subscription needed.
- **Direct-grant users** — individual account assignments (no group); `getUserPolicy` returns
  `policy: null`; account discovery depends entirely on the realtime WebSocket.

---

## 1. `--yes` does not skip interactive prompts — only the final confirmation

**What you'd expect:** `--yes` bypasses all prompts so the command is fully non-interactive.

**What actually happens:** `--yes` skips only the final "Submit? [y/N]" confirmation
(step 8 above). Every upstream collection prompt — account display name, permission set
selection, duration, justification — still calls `mustPromptLine()`, which reads from
stdin and exits with `Error: stdin closed` on EOF.

The flag literally guards a single `if !*yes { … }` block around the summary + confirm
prompt. Nothing before it is conditioned on `--yes`.

**Workaround:** Provide all required flags upfront so no prompts are reached:
```sh
awsup request \
  --account <12-digit-id-or-display-name> \
  --role <arn-or-display-name> \
  --duration 1 \
  --justification "reason" \
  --yes
```
With all four flags set, the code bypasses every `mustPromptLine` call and `--yes`
cleanly skips the one confirmation it was designed to skip.

---

## 2. Direct-grant users cannot discover their own accounts

**What happens:** Realtime entitlement autodiscovery fails with
`unauthorized: connection_error`, so the tool falls through to a manual prompt for the
account ID with no list to choose from.

**How realtime discovery works (when it succeeds):**

The CLI opens a WebSocket to the AppSync realtime endpoint
(`appsync-realtime-api.<region>.amazonaws.com/graphql/realtime`) and subscribes to the
`OnPublishPolicy` subscription. It then waits up to 7 seconds for the backend to push a
data frame. The backend publishes one when it detects an active SSO session. On success
the frame contains `{ accounts[{name, id}], permissions[{name, id}] }` — real display
names and IDs together.

When realtime fails, there is no API that returns a list of accounts for direct-grant
users. The `getMgmtPermissions` fallback (step 5) provides ARN-only permission sets but
has no account equivalent at all.

**`awsup options` output when realtime is broken vs working:**
```
# broken (no access token in cache)
Debug: realtime entitlements: unauthorized: connection_error
Accounts: (not discoverable — provide --account <id> to request)
Permission sets:
  arn:aws:sso:::permissionSet/ssoins-.../ps-e1556f15cb90c33f
  ...

# working (fresh access token)
Accounts:
  VU-Research-ISIS-ScopeLab (343084147688)
  ...
Permission sets:
  VU_PowerUserAccess (arn:aws:sso:::permissionSet/ssoins-.../ps-2f5c1ceaaf330741)
  ...
```

**Workaround:** Fix the cache (see pitfall #5), or provide `--account <12-digit-id>`
directly if you already know it.

---

## 3. `--account` accepts display names but the backend validates by ID

**What happens:** Passing `--account scopelab` does not produce an immediate error.
The string is used as-is as `accountId` in the `validateRequest` and `createRequests`
GraphQL calls. The server then rejects it:
```
Error: request not valid: Account not in user's eligible accounts or OUs
```
This reads like an authorization error, not a bad-input error.

**How account resolution works:**

For group-policy users, the CLI runs `resolveByIDOrName(policy.Accounts, input, …)`,
which does:
```
id == input  (exact 12-digit match)
OR
strings.EqualFold(name, input)  (case-insensitive display-name match)
```
If nothing matches, it exits immediately with a clear "not found" error listing available
accounts.

For direct-grant users, if realtime succeeds the same `resolveByIDOrName` logic runs
against the realtime-returned accounts. If realtime fails there is no list to match
against, so the raw flag string is passed straight through as both `accountId` and
`accountName`. No format validation is done before the GraphQL call.

**Workaround:** Always pass the 12-digit account ID when you are a direct-grant user
without working realtime. With working realtime the display name (`VU-Research-ISIS-ScopeLab`)
resolves correctly.

---

## 4. Permission sets show as ARN-only when realtime is broken

**What happens:** The `getMgmtPermissions` query returns:
```graphql
{ getMgmtPermissions { permissions } }
# permissions: ["arn:aws:sso:::permissionSet/ssoins-.../ps-e1556f15...", ...]
```
It is a flat `[String]` array of ARNs — no names. The Go code creates
`Permission{Name: arn, ID: arn}` for each entry, so both fields are the ARN string.
The interactive selection list and `awsup options` therefore show only bare ARNs.

**How display names are added (when realtime works):**

`awsup options` merges the two sources: the `getMgmtPermissions` ARN list and the
realtime `OnPublishPolicy` permission list (which has `{name, id}` pairs). For each
entry in the ARN list it looks up a matching entry in the realtime list by ID, and
replaces the ARN-as-name with the real display name. Entries that appear only in the
realtime list are appended. This produces the enriched output:
```
VU_PowerUserAccess (arn:aws:sso:::permissionSet/ssoins-.../ps-2f5c1ceaaf330741)
```

**How `--role` matching works:** When `--role` is provided and realtime is working,
`resolveByIDOrName` checks the merged list by exact ARN match or
`strings.EqualFold(name, input)`. So `--role VU_PowerUserAccess` resolves correctly.
When realtime is broken and only ARNs are available, `--role poweruser` matches
nothing and is passed through verbatim, which causes `validateRequest` to fail.

**Workaround:** Fix the cache (pitfall #5), or use the full ARN:
```sh
awsup request --role arn:aws:sso:::permissionSet/ssoins-.../ps-2f5c1ceaaf330741 ...
```

---

## 5. Stale credentials cache blocks realtime discovery

**What happens:** The CLI may have written a credentials cache
(`~/.config/awsup/default.credentials`) that contains an `idToken` and `refreshToken`
but no `accessToken`. AppSync's realtime WebSocket channel requires the **Cognito access
token** in the `Authorization` header — it rejects the ID token. Without it, every
realtime attempt fails with `unauthorized: connection_error`.

**How the credentials cache works:**

`GetValid(cachePath, appClientID, userPoolID, hostedUIDomain)` runs this logic on every
CLI invocation:

```
1. Load cache file
2. If AppClientID or UserPoolID mismatch → discard
3. If ExpiresAt > now+60s → return cached (fast path — no browser read)
4. If RefreshToken present → POST /oauth2/token?grant_type=refresh_token
     → on success: new idToken + accessToken written to cache
     → on failure: fall through
5. auth.FromBrowser() → read Chromium LevelDB localStorage
     → on success: fresh idToken + accessToken + refreshToken written to cache
```

The fast path (step 3) is the trap. If the cache was populated without an `accessToken`
(e.g. from an early `awsup init` run that read an incomplete browser session), and the
`idToken` is still within its ~1-hour lifetime, the cache is returned as-is and the
browser is never re-read. All subsequent invocations hit the same stale cache.

**How the WebSocket auth uses the token:**

`RealtimeToken()` returns `accessToken` if non-empty, otherwise `idToken`. The realtime
endpoint is derived by replacing `appsync-api` with `appsync-realtime-api` in the HTTPS
URL and converting to `wss://`. The token is sent in the `Sec-WebSocket-Protocol` header
as a base64-encoded JSON blob:
```json
{"Authorization": "<token>", "host": "<appsync-api-host>"}
```
AppSync validates this at the WebSocket handshake. An ID token here causes an immediate
`connection_error` frame before any subscription is registered.

**Fix:**
```sh
rm ~/.config/awsup/default.credentials
```
The next command reads `auth.FromBrowser()`, which re-scans Chromium's LevelDB storage
for an active TEAM session, extracts the full token set (including `accessToken`), and
writes a new cache file. The browser must be open and signed into TEAM.

**Note:** Simply signing into TEAM in the browser is not enough — the stale cache must
be deleted first, because the validity check only looks at `ExpiresAt`, not at whether
`accessToken` is populated.

---

## 6. Realtime subscription times out because `getUserPolicy` fires the push before the CLI subscribes

**Symptom:**
```
Debug: realtime entitlements: context deadline exceeded
Accounts: (not discoverable — provide --account <id> to request)
```

**Why it happens:**

`onPublishPolicy` is a push subscription — the backend only sends a data frame when
something triggers it. Based on the browser's network traffic (HAR), the trigger is
`GetUserPolicy` completing: the push arrives ~900ms after that call returns, ~1.4s after
the subscription is established.

The browser starts `GetUserPolicy`, `GetMgmtPermissions`, and the WebSocket subscription
**in parallel**, so the WebSocket is already subscribed and waiting when `GetUserPolicy`
completes and the push fires.

The CLI does them **sequentially**:

```
CLI order:
  1. getUserPolicy()           ← triggers backend push
  2. (push fires — nobody listening)
  3. WebSocket subscribe()     ← too late; push already sent
  4. wait 7 seconds...
  5. context deadline exceeded
```

The 7-second timeout is not the issue — the backend push simply never arrives because
the CLI missed it. Whether `awsup options` succeeds depends on whether something else
(e.g., the browser actively loading the TEAM page simultaneously) happens to trigger a
second push while the CLI is subscribed.

**Fix:** Start the WebSocket subscription concurrently with `getUserPolicy` rather than
after it returns. The subscription setup needs to happen before — or at least in parallel
with — the HTTP call that triggers the push. In practice this means restructuring
`runOptions` and `runRequest` to kick off the realtime goroutine before calling
`policy.Get`, and cancelling it if the user turns out to be a group-policy user (non-nil
policy).

---

## Summary table

| Pitfall | Severity | Workaround |
|---------|----------|------------|
| `--yes` only skips final confirm | Medium | Provide all flags explicitly |
| No account discovery for direct-grant | High | Know the 12-digit account ID |
| Display name silently treated as account ID | High | Always use 12-digit account ID |
| ARN-only permission set names | Medium | Fix realtime auth (pitfall #5) |
| Stale cache lacks access token, breaks realtime | High | `rm ~/.config/awsup/default.credentials` |
