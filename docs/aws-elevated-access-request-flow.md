# AWS TEAM — Elevated Access Request Submission Flow

## Overview

The browser app at `${TEAM_FRONTEND_URL}` is an instance of the AWS Samples **TEAM (Temporary Elevated Access Management)** project ([aws-samples/iam-identity-center-team](https://github.com/aws-samples/iam-identity-center-team)). It lets a user request a time-bounded elevation into an AWS account / IAM Identity Center permission set, routes the request to approvers, and (on approval) provisions and later revokes the account assignment.

There is no documented public REST API for the request workflow. The web UI talks exclusively to a single AWS AppSync GraphQL endpoint. This document describes the end-to-end "submit a new request" flow as observed in a HAR capture.

The deployment-specific identifiers (frontend URL, AppSync endpoint, Cognito IDs) are kept in [.env](.env). Every TEAM deployment generates its own values; throughout this document they appear as `${TEAM_*}` placeholders.

| Resource | Variable |
|---|---|
| Frontend | `${TEAM_FRONTEND_URL}` |
| AppSync GraphQL | `${TEAM_APPSYNC_ENDPOINT}` |
| AppSync auth mode | `${TEAM_APPSYNC_AUTH_MODE}` (= `AMAZON_COGNITO_USER_POOLS`) |
| Cognito User Pool | `${TEAM_COGNITO_USER_POOL_ID}` |
| App client ID | `${TEAM_COGNITO_APP_CLIENT_ID}` |
| Hosted UI domain | `${TEAM_COGNITO_HOSTED_UI_DOMAIN}` |
| Federated IdP | `${TEAM_COGNITO_IDP_NAME}` (SAML/OIDC; usernames are prefixed `<idp>_…`) |
| OAuth scopes | `${TEAM_COGNITO_OAUTH_SCOPES}` |
| OAuth redirect | `${TEAM_COGNITO_OAUTH_REDIRECT}` |
| Identity Pool | `${TEAM_COGNITO_IDENTITY_POOL_ID}` |

## Token Types and Their Uses

The Cognito Hosted UI authorization-code + PKCE exchange returns two tokens relevant to this API:

| Token | Claim `token_use` | Used for |
|---|---|---|
| **ID token** | `id` | All AppSync **HTTP** GraphQL requests (`Authorization` header) |
| **Access token** | `access` | AppSync **WebSocket** realtime subscriptions (`Sec-WebSocket-Protocol` auth header) |

Both tokens are JWTs signed by Cognito. AppSync validates the signature and audience (`aud` / `client_id`) and rejects the wrong token type for each channel — using the ID token on a WebSocket connection returns `connection_error: unauthorized`.

## Prerequisites

### Organizational access

To use this API you need three things provisioned by the TEAM administrator:

1. **An account in the identity provider.** Sign-in is federated through enterprise SSO (IAM Identity Center). There is no direct Cognito username/password path — the Cognito client is configured for federated IdP only.

2. **An entitlement grant in TEAM.** This is either a group-based grant (membership in an IAM Identity Center group that has been assigned `(account, permission set)` pairs in TEAM's entitlement matrix) or a direct account grant (your Identity Center user is granted specific accounts directly). `getUserPolicy` returns `policy: null` for direct-grant users — this is expected and does not mean you have no access. In both cases `validateRequest` is the authoritative check. Contact your TEAM admin if `validateRequest` returns `valid: false`.

3. **MFA enrolled.** The sign-in flow requires a TOTP code at every login. Enroll a TOTP authenticator app in your IAM Identity Center account before attempting to use the API.

### API credential

The only credential the API requires is a valid **Cognito User Pool ID token (JWT)** for the deployment's user pool, sent in the `Authorization` header. HAR exports strip that header by default, but the endpoint's behavior is deterministic:

```
$ curl -sS -X POST "$TEAM_APPSYNC_ENDPOINT" \
       -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
{"errors":[{"errorType":"UnauthorizedException","message":"Valid authorization header not provided."}]}
```

CORS preflight confirms the contract — only `content-type, authorization, x-amz-user-agent` are accepted, ruling out SigV4 and API key auth:

```
access-control-allow-headers: content-type,authorization,x-amz-user-agent
access-control-allow-methods: POST
```

To obtain tokens, complete the Cognito Hosted UI Authorization Code + PKCE flow. The federated IdP routes through enterprise SSO + TOTP MFA — this cannot be automated. The `/oauth2/token` code exchange returns both the `id_token` and `access_token` JWTs. The `id_token` carries all HTTP GraphQL calls; the `access_token` is required for WebSocket subscriptions (see [Token Types and Their Uses](#token-types-and-their-uses)). Both tokens contain `userId` and `groupIds` as custom claims (IAM Identity Center identifiers), injected by the User Pool at issuance; callers never need to resolve these separately.

## Common Request Shape

Every call is the same shape — only the GraphQL query/variables change.

**Request:** `POST ${TEAM_APPSYNC_ENDPOINT}`

| Header | Value |
|---|---|
| `authorization` | `<Cognito User Pool ID token (JWT)>` (no `Bearer ` prefix) |
| `content-type` | `application/json; charset=UTF-8` |
| `accept` | `application/json, text/plain, */*` |
| `origin` | `${TEAM_FRONTEND_URL}` |
| `referer` | `${TEAM_FRONTEND_URL}/` |
| `x-amz-user-agent` | `${TEAM_AMPLIFY_USER_AGENT}` |

**Body:** `{ "query": "<GraphQL document>", "variables": { … } }`

The user identity (`username`, `email`, the implicit `owner` on records created) is taken from the JWT claims server-side — clients never pass identity in the body.

## Entitlement Discovery (Page Load)

Before the request form is usable, the UI determines what accounts and permission sets the user is eligible to request. This is a separate pre-request flow that precedes `validateRequest`/`createRequests`.

### `getUserPolicy` — group-policy vs direct-grant detection

```graphql
query GetUserPolicy($userId: String, $groupIds: [String]) {
  getUserPolicy(userId: $userId, groupIds: $groupIds) {
    id
    policy {
      accounts { name id __typename }
      permissions { name id __typename }
      approvalRequired
      duration
      __typename
    }
    username
    __typename
  }
}
```

**Variables:** `{ "userId": "<identity-store-user-id>", "groupIds": ["<group-id>", …] }`

**Response (group-policy user):** `policy` is a non-null object with `accounts` and `permissions` arrays — the client populates the form dropdowns from these directly.

**Response (direct-grant user):** `policy` is `null`. This is **not** an error. It means the user has been granted accounts via a direct Identity Center assignment rather than group membership. Entitlements must be discovered via realtime subscription (see below).

### `getMgmtPermissions` — management permission sets (direct-grant only)

For direct-grant users, an additional query returns the set of permission-set ARNs configured for management grants:

```graphql
query GetMgmtPermissions {
  getMgmtPermissions {
    permissions
    __typename
  }
}
```

**Response:** `{ "getMgmtPermissions": { "permissions": ["arn:aws:sso:::permissionSet/…", …] } }`

This returns ARN strings only — no display names. Display names for these permission sets come from the `onPublishPolicy` realtime subscription (see below). If `getMgmtPermissions` returns an empty list, the user must enter the ARN manually.

### `onPublishPolicy` — realtime entitlement subscription (direct-grant only)

For direct-grant users, the UI subscribes to an AppSync realtime event that delivers the user's actual entitlements (account + permission set pairs). This uses the AppSync WebSocket realtime endpoint, which is distinct from the HTTP GraphQL endpoint.

#### WebSocket endpoint and authentication

| | HTTP (GraphQL queries/mutations) | WebSocket (realtime subscriptions) |
|---|---|---|
| Endpoint | `https://<id>.appsync-api.<region>.amazonaws.com/graphql` | `wss://<id>.appsync-realtime-api.<region>.amazonaws.com/graphql` |
| Auth token | **ID token** (`Authorization` header) | **Access token** (`Sec-WebSocket-Protocol` header) |

Auth for the WebSocket channel is carried entirely in the `Sec-WebSocket-Protocol` HTTP upgrade header — **not** in the URL, query parameters, or `connection_init` payload. Passing the ID token here returns `connection_error: unauthorized`; the access token is required.

The subprotocol list sent in the header:
```
Sec-WebSocket-Protocol: graphql-ws, header-<base64({"Authorization":"<access-token>","host":"<appsync-realtime-host>"})>
```

The base64 payload is standard (not URL-safe) encoding of a JSON object with exactly two keys: `Authorization` (the access token, no `Bearer` prefix) and `host` (the realtime hostname, e.g. `abc.appsync-realtime-api.us-east-1.amazonaws.com`).

#### Frame protocol (graphql-ws / subscriptions-transport-ws)

```
CLIENT → { "type": "connection_init" }
SERVER → { "type": "connection_ack" }
CLIENT → { "id": "1", "type": "start", "payload": <start-payload> }
SERVER → { "id": "1", "type": "start_ack" }   (may be omitted)
SERVER → { "type": "ka" }                      (keepalive; ignore)
SERVER → { "id": "1", "type": "data", "payload": { "data": { "onPublishPolicy": { … } } } }
CLIENT → { "id": "1", "type": "complete" }     (client closes after first usable frame)
```

The `start` message payload is a JSON object with two keys:
- `data`: JSON string of `{ "query": "<subscription-document>", "variables": {} }`
- `extensions.authorization`: object with `Authorization` (access token), `host`, and `x-amz-user-agent`

#### Subscription document

```graphql
subscription OnPublishPolicy {
  onPublishPolicy {
    id
    policy {
      accounts { name id __typename }
      permissions { name id __typename }
      approvalRequired
      duration
      __typename
    }
    username
    __typename
  }
}
```

Note: **no arguments**. The server returns entitlements for the authenticated user based on the access token. The subscription does not accept `userId` or `groupIds` parameters.

#### Response structure

The `data` payload within a `data` frame:

```json
{
  "data": {
    "onPublishPolicy": {
      "id": "<policy-id>",
      "username": "<cognito-username>",
      "policy": [
        {
          "accounts": [{ "name": "My Account", "id": "123456789012" }],
          "permissions": [{ "name": "PowerUserAccess", "id": "arn:aws:sso:::permissionSet/…" }],
          "approvalRequired": true,
          "duration": "8"
        }
      ]
    }
  }
}
```

`policy` is a **list of entitlement objects**, where each typically represents one `(account, permission set)` pair. A user with access to N accounts across M permission sets may receive up to N×M entitlement objects — the client deduplicates across the list. A usable payload has at least one non-empty `accounts` or `permissions` list; the client waits for the first usable frame and closes the subscription.

## The Flow

The captured trace covers a user opening the "request access" page, submitting one request, and the page polling its state. There are five distinct GraphQL operations involved.

### Step 1: Pre-flight — `validateRequest`

Before the user can submit, the UI verifies that the chosen `(account, permissionSet)` is actually one this user (or one of their group memberships) is entitled to request. This is a server-side enforcement of the entitlement matrix the TEAM admin defines.

**Mutation:**
```graphql
mutation ValidateRequest(
  $accountId: String!
  $roleId: String!
  $userId: String!
  $groupIds: [String]!
) {
  validateRequest(
    accountId: $accountId
    roleId: $roleId
    userId: $userId
    groupIds: $groupIds
  ) {
    valid
    reason
  }
}
```

**Variables:**
| Field | Description | Example shape |
|---|---|---|
| `accountId` | 12-digit AWS account ID being requested | `"<aws-account-id>"` |
| `roleId` | ARN of the IAM Identity Center permission set | `"arn:aws:sso:::permissionSet/<sso-instance-id>/<permission-set-id>"` |
| `userId` | Identity Center user ID (UUID with store-id prefix) | `"<identitystore-id>-<user-uuid>"` |
| `groupIds` | Identity Center group IDs the user belongs to. May contain a trailing empty string. | `["<identitystore-id>-<group-uuid>", …, ""]` |

The `userId` and `groupIds` are AWS Identity Center identity-store identifiers injected into the Cognito ID token as **custom JWT claims** (`userId` string, `groupIds` comma-separated string with trailing comma). They are parsed directly from the JWT — no Identity Store API calls are needed. The server independently authenticates via the JWT signature; these IDs are inputs to the entitlement check.

**Response:**
```json
{
  "data": {
    "validateRequest": {
      "valid": true,
      "reason": "Direct account grant"
    }
  }
}
```

`reason` is a human-readable explanation (`"Direct account grant"`, `"OU grant"`, `"Group membership"`, etc.). If `valid` is `false`, the UI blocks submission.

### Step 2: Create the request — `createRequests`

If validation passes, the UI submits the request. The record lands in DynamoDB with `status: "pending"` and triggers the approval workflow (notifications, etc.) on the backend.

**Mutation:**
```graphql
mutation CreateRequests(
  $input: CreateRequestsInput!
  $condition: ModelRequestsConditionInput
) {
  createRequests(input: $input, condition: $condition) {
    id email accountId accountName role roleId
    startTime duration justification status comment
    username approver approverId approvers approver_ids
    revoker revokerId endTime ticketNo revokeComment
    session_duration createdAt updatedAt owner __typename
  }
}
```

**Input fields the UI sends:**
| Field | Notes |
|---|---|
| `accountId` | Same 12-digit ID as Step 1 |
| `accountName` | Display name; resolved client-side from the account list |
| `role` | Permission-set display name |
| `roleId` | Permission set ARN (same as Step 1's `roleId`) |
| `duration` | Hours, as a string. Must be `≤ Settings.duration` (Step 3). |
| `startTime` | ISO 8601 with offset, e.g. `"YYYY-MM-DDTHH:MM:SS-05:00"` |
| `justification` | Free-form business reason |
| `ticketNo` | Optional ticket reference; required iff `Settings.ticketNo == true` |

**Fields the server fills in:**
| Field | Source |
|---|---|
| `id` | Server-generated UUID |
| `username` | Cognito `cognito:username` claim from the JWT (e.g. `"<idp>_<user-email>"`) |
| `owner` | Same as `username` — used by the AppSync `@auth` rule to scope reads/updates to the requester |
| `email` | Initially `null` — populated later by the workflow (resolved from Identity Center) |
| `status` | `"pending"` |
| `approvers`, `approver_ids` | Initially `null` — populated when the workflow resolves the approver group |
| `createdAt`, `updatedAt` | Server timestamps (UTC ISO 8601 with `Z`) |

The `email` returned in subsequent list queries (Step 4) carries the SSO email casing as Identity Center stores it (mixed case), distinct from the lower-cased Cognito `username`. The `<idp>_` prefix on the username comes from the IdP attribute mapping for the federated provider.

### Step 3: Load deployment settings — `getSettings`

The settings record is a singleton with primary key `id = "settings"`. It controls UI affordances and server-side constraints (max request duration, whether comments are required, whether approval is enforced, notification toggles, admin/auditor groups).

```graphql
query GetSettings($id: ID!) {
  getSettings(id: $id) {
    id duration expiry comments ticketNo approval modifiedBy
    sesNotificationsEnabled snsNotificationsEnabled
    slackNotificationsEnabled slackAuditNotificationsChannel
    sesSourceEmail sesSourceArn slackToken
    teamAdminGroup teamAuditorGroup useOUCache
    createdAt updatedAt __typename
  }
}
```

**Variables:** `{ "id": "settings" }`

**Response (shape):**
```json
{
  "data": {
    "getSettings": {
      "id": "settings",
      "duration": "<max-hours>",
      "expiry": "<days>",
      "comments": true,
      "ticketNo": false,
      "approval": true,
      "modifiedBy": "<cognito-username-of-last-editor>",
      "sesNotificationsEnabled": false,
      "snsNotificationsEnabled": false,
      "slackNotificationsEnabled": false,
      "slackAuditNotificationsChannel": "",
      "sesSourceEmail": "",
      "sesSourceArn": "",
      "slackToken": "",
      "teamAdminGroup": "<admin-group-identifier>",
      "teamAuditorGroup": "<auditor-group-identifier>",
      "useOUCache": false,
      "createdAt": "<iso-timestamp>",
      "updatedAt": "<iso-timestamp>",
      "__typename": "Settings"
    }
  }
}
```

| Field | Meaning |
|---|---|
| `duration` | Max request hours (the form's slider cap) |
| `expiry` | Days the request stays actionable before auto-expiring |
| `comments` | Whether the justification field is required |
| `ticketNo` | Whether a ticket reference is required |
| `approval` | If `false`, requests auto-approve |
| `teamAdminGroup` / `teamAuditorGroup` | Group memberships that grant admin / auditor UI access |
| `slackToken` / `sesSourceArn` / etc. | Empty when the corresponding notification channel is disabled |

In the captured trace this query runs *after* `createRequests`. The UI almost certainly fetches it on first render too (cached in client state); the HAR happens to start at the moment the user clicked "Submit," so the earlier read isn't in the capture.

### Step 4: List the user's requests — `requestByEmailAndStatus`

After submit, the UI navigates to the "My Requests" view and reads the user's history. The same query is repeated several times in the capture (routing, focus regain, post-mutation refresh) — it is **not** a GraphQL subscription; the UI polls.

```graphql
query RequestByEmailAndStatus(
  $email: String!
  $status: ModelStringKeyConditionInput
  $sortDirection: ModelSortDirection
  $filter: ModelrequestsFilterInput
  $limit: Int
  $nextToken: String
) {
  requestByEmailAndStatus(
    email: $email
    status: $status
    sortDirection: $sortDirection
    filter: $filter
    limit: $limit
    nextToken: $nextToken
  ) {
    items { id email accountId accountName role roleId
            startTime duration justification status comment
            username approver approverId approvers approver_ids
            revoker revokerId endTime ticketNo revokeComment
            session_duration createdAt updatedAt owner __typename }
    nextToken
    __typename
  }
}
```

**Variables observed:** `{ "email": "<user-email-as-stored-in-identity-center>", "nextToken": null }`

The `email` is the SSO email **as Identity Center stores it** (mixed case). The query is backed by a DynamoDB GSI (`requestByEmailAndStatus`), so passing the wrong casing yields zero rows — the UI uses the value from the JWT's `email` claim verbatim.

`status` and `filter` are unused in the captured calls — the UI fetches every request for the user and partitions client-side by `status`. `nextToken` paginates when there are more rows than the page size.

The newly-created record is returned with `status: "pending"`, `approvers: null`, `approver_ids: null`. Once the backend approval-resolver Lambda runs (asynchronously), subsequent polls return the populated approver arrays. Once an approver acts, `status` transitions through `approved` → `scheduled` → `in progress` → `ended` (or `rejected` / `expired` / `revoked`), and the matching timestamp/actor fields fill in.

## Sequence

### Group-policy users

```
PAGE LOAD
        │
        ▼
[0] query getUserPolicy                         ──► { policy: { accounts: […], permissions: […] } }
        │  (populates form dropdowns)
        ▼
USER CLICKS "SUBMIT"
        │
        ▼
[1] mutation validateRequest                    ──► { valid: true, reason: "Group membership" }
        │  (entitlement check)
        ▼
[2] mutation createRequests                     ──► { id: <uuid>, status: "pending", … }
        │
        ▼
[3] query getSettings / [4] query requestByEmailAndStatus (×N)
```

### Direct-grant users

```
PAGE LOAD
        │
        ▼
[0a] query getUserPolicy                        ──► { policy: null }  (direct-grant signal)
[0b] query getMgmtPermissions                   ──► { permissions: ["arn:…", …] }
[0c] WebSocket → subscribe onPublishPolicy      ──► { policy: [{ accounts:[…], permissions:[…] }] }
        │  (access token in Sec-WebSocket-Protocol header; first usable frame returned)
        │  (deduplicates entitlement list into account/permission set dropdowns)
        ▼
USER CLICKS "SUBMIT"
        │
        ▼
[1] mutation validateRequest                    ──► { valid: true, reason: "Direct account grant" }
        ▼
[2] mutation createRequests                     ──► { id: <uuid>, status: "pending", … }
        │
        ▼
[3] query getSettings / [4] query requestByEmailAndStatus (×N)
```

## Authentication Summary

| Step | Channel | Token | Notes |
|---|---|---|---|
| Cognito Hosted UI sign-in | HTTPS redirect | — | Federated SAML/OIDC; produces ID token + access token |
| `getUserPolicy`, `getMgmtPermissions` | HTTP POST | **ID token** | `Authorization` header, no `Bearer` prefix |
| `validateRequest`, `createRequests` | HTTP POST | **ID token** | Same |
| `getSettings`, `requestByEmailAndStatus` | HTTP POST | **ID token** | Same |
| `onPublishPolicy` subscription | WebSocket | **Access token** | `Sec-WebSocket-Protocol: graphql-ws, header-<b64>` |

There are no CSRF tokens or per-request nonces. Token lifetime is the user-pool default (1 hour); the Amplify SDK silently refreshes via the refresh token stored in browser localStorage.

## Caveats

- This is an **internal** API — undocumented and tenant-specific. The schema can change with any redeploy of the TEAM stack.
- HAR exports do not include `Authorization` (Chrome's HAR exporter strips `Cookie` and `Authorization` by default). The auth contract above was confirmed by probing the endpoint, not by reading captured headers.
- `userId` and `groupIds` in `validateRequest` are custom claims in the Cognito ID token (`userId`: string, `groupIds`: comma-separated string with trailing comma). They are injected at token issuance by the User Pool and are available directly from the JWT — no Identity Store API calls required.
- `accountName` and `role` (display name) are convenience fields the client populates from entitlement discovery; only `accountId` and `roleId` are authoritative.
- The `email` GSI key is case-sensitive. Use the exact casing from the JWT `email` claim, not lower-cased.
- The federated IdP forces enterprise SSO; there is no direct Cognito sign-in path for human users on this deployment.
- Request mutation uses an AppSync `@auth(rules: [{ allow: owner, ownerField: "owner" }])`-style rule keyed on the JWT `cognito:username` claim — you can only see/modify your own request rows unless you hold a privileged group membership (`teamAdminGroup` / `teamAuditorGroup`).
- **WebSocket auth pitfall:** Passing the ID token (not the access token) in the `Sec-WebSocket-Protocol` header results in an immediate `connection_error` frame; the error message does not distinguish wrong-token-type from wrong-token-value.
- **gorilla/websocket behavior:** After any read error (including a deadline timeout), the gorilla/websocket library marks the connection permanently failed. Subsequent `ReadJSON` calls panic with "repeated read on failed websocket connection". Set `SetReadDeadline` once to the context deadline rather than in a polling loop.
- **`onPublishPolicy` has no arguments.** An earlier assumption that it accepted `$userId`/`$groupIds` parameters was wrong — the server filters entitlements from the access token identity, not caller-provided IDs. Passing variables to this subscription is silently ignored or errors.
