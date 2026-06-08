package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/drogers0/awsup/internal/appsync"
	"github.com/gorilla/websocket"
)

// Account represents an AWS account the user may request access to.
type Account struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Permission represents a permission set the user may request.
type Permission struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Policy holds the set of accounts and permission sets a user is entitled to
// request, along with request parameters.
type Policy struct {
	Accounts         []Account    `json:"accounts"`
	Permissions      []Permission `json:"permissions"`
	ApprovalRequired bool         `json:"approvalRequired"`
	Duration         int          `json:"duration"`
}

// UserPolicy is the top-level response type. Policy is nil for direct-grant
// users (not an error).
type UserPolicy struct {
	ID       string  `json:"id"`
	Username string  `json:"username"`
	Policy   *Policy `json:"policy"`
}

const getUserPolicyQuery = `
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
}`

type getUserPolicyVars struct {
	UserID   string   `json:"userId"`
	GroupIDs []string `json:"groupIds"`
}

type getUserPolicyData struct {
	GetUserPolicy *UserPolicy `json:"getUserPolicy"`
}

// Get fetches the user's policy from AppSync. It returns a UserPolicy whose
// Policy field may be nil for direct-grant users.
func Get(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*UserPolicy, error) {
	vars := getUserPolicyVars{UserID: userID, GroupIDs: groupIDs}
	data, err := appsync.Execute[getUserPolicyData](ctx, c, getUserPolicyQuery, vars)
	if err != nil {
		return nil, fmt.Errorf("getUserPolicy: %w", err)
	}
	if data.GetUserPolicy == nil {
		return nil, fmt.Errorf("getUserPolicy returned null")
	}
	return data.GetUserPolicy, nil
}

// onPublishPolicySubscription has no arguments; auth is carried in the
// Sec-WebSocket-Protocol header and in the start-message extensions.
const onPublishPolicySubscription = `
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
}`

type wsMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type subscriptionExtensions struct {
	Authorization map[string]string `json:"authorization"`
}

type subscriptionStartPayload struct {
	Data       string                 `json:"data"`
	Extensions subscriptionExtensions `json:"extensions"`
}

type subscriptionRequest struct {
	Query     string `json:"query"`
	Variables any    `json:"variables"`
}

// realtimeEntitlement is one (account, permission-set) grant in an
// onPublishPolicy data frame.
type realtimeEntitlement struct {
	Accounts         []Account    `json:"accounts"`
	Permissions      []Permission `json:"permissions"`
	ApprovalRequired bool         `json:"approvalRequired"`
	Duration         string       `json:"duration"`
}

// realtimePolicy is the top-level object returned by onPublishPolicy.
type realtimePolicy struct {
	ID       string                `json:"id"`
	Username string                `json:"username"`
	Policy   []realtimeEntitlement `json:"policy"`
}

type onPublishDataFrame struct {
	Data struct {
		OnPublishPolicy *realtimePolicy `json:"onPublishPolicy"`
	} `json:"data"`
}

type connectionErrorFrame struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

// wsDialContext is replaceable in tests to avoid live websocket connections.
var wsDialContext = func(ctx context.Context, wsURL string, subprotocols []string) (*websocket.Conn, *http.Response, error) {
	dialer := websocket.Dialer{Subprotocols: subprotocols}
	return dialer.DialContext(ctx, wsURL, nil)
}

// deriveRealtimeEndpoint converts an AppSync HTTPS endpoint to a WSS URL and
// returns the Sec-WebSocket-Protocol subprotocols that carry the auth token
// (a Cognito ID or access token — either is accepted on the WebSocket channel).
func deriveRealtimeEndpoint(endpoint, token string) (wsURL, apiHost string, subprotocols []string, err error) {
	u, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return "", "", nil, &appsync.NetworkError{Op: "derive realtime endpoint", Err: fmt.Errorf("invalid AppSync endpoint: %w", parseErr)}
	}
	if u.Scheme != "https" || !strings.Contains(u.Host, "appsync-api") {
		return "", "", nil, &appsync.NetworkError{Op: "derive realtime endpoint", Err: fmt.Errorf("invalid AppSync endpoint")}
	}
	apiHost = u.Host
	headerJSON, _ := json.Marshal(map[string]string{
		"Authorization": token,
		"host":          apiHost,
	})
	rtU := *u
	rtU.Scheme = "wss"
	rtU.Host = strings.Replace(u.Host, "appsync-api", "appsync-realtime-api", 1)
	// RawURLEncoding (not StdEncoding): Sec-WebSocket-Protocol values are HTTP
	// tokens and cannot contain '+', '/', or '=' padding, which AppSync rejects
	// with "The request headers are invalid."
	subprotocols = []string{
		"graphql-ws",
		"header-" + base64.RawURLEncoding.EncodeToString(headerJSON),
	}
	return rtU.String(), apiHost, subprotocols, nil
}

// flattenEntitlements merges all (account, permission) pairs from an
// onPublishPolicy response into a single Policy, deduplicating by ID.
func flattenEntitlements(entitlements []realtimeEntitlement) *Policy {
	seenAccts := map[string]bool{}
	seenPerms := map[string]bool{}
	p := &Policy{Accounts: []Account{}, Permissions: []Permission{}}
	for _, ent := range entitlements {
		for _, a := range ent.Accounts {
			if !seenAccts[a.ID] {
				seenAccts[a.ID] = true
				p.Accounts = append(p.Accounts, a)
			}
		}
		for _, perm := range ent.Permissions {
			if !seenPerms[perm.ID] {
				seenPerms[perm.ID] = true
				p.Permissions = append(p.Permissions, perm)
			}
		}
	}
	return p
}

func writeWSJSON(conn *websocket.Conn, v any) error {
	if err := conn.WriteJSON(v); err != nil {
		return &appsync.NetworkError{Op: "write realtime frame", Err: err}
	}
	return nil
}

func sendComplete(conn *websocket.Conn, id string) {
	if id == "" {
		id = "1"
	}
	_ = writeWSJSON(conn, wsMessage{ID: id, Type: "complete"})
}

func readWSMessage(ctx context.Context, conn *websocket.Conn) (wsMessage, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	var msg wsMessage
	if err := conn.ReadJSON(&msg); err != nil {
		if ctx.Err() != nil {
			return wsMessage{}, ctx.Err()
		}
		if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
			return wsMessage{}, context.DeadlineExceeded
		}
		return wsMessage{}, &appsync.NetworkError{Op: "read realtime frame", Err: err}
	}
	return msg, nil
}

// GetOnPublishPolicyEntitlements subscribes to the realtime OnPublishPolicy
// stream and returns the first usable entitlement payload. A usable payload has
// at least one non-empty list (accounts or permissions). Missing lists are
// returned as empty slices.
func GetOnPublishPolicyEntitlements(ctx context.Context, c *appsync.Client, userID string, groupIDs []string) (*Policy, error) {
	wsURL, apiHost, subprotocols, err := deriveRealtimeEndpoint(c.Endpoint(), c.RealtimeToken())
	if err != nil {
		return nil, err
	}

	conn, _, err := wsDialContext(ctx, wsURL, subprotocols)
	if err != nil {
		return nil, &appsync.NetworkError{Op: "dial realtime", Err: err}
	}
	defer conn.Close()

	// Auth is in the Sec-WebSocket-Protocol header; connection_init needs no payload.
	if err := writeWSJSON(conn, wsMessage{Type: "connection_init"}); err != nil {
		return nil, err
	}

	for {
		msg, err := readWSMessage(ctx, conn)
		if err != nil {
			return nil, err
		}
		switch msg.Type {
		case "connection_ack":
			goto subscribed
		case "connection_error":
			var ce connectionErrorFrame
			_ = json.Unmarshal(msg.Payload, &ce)
			message := ce.Message
			if message == "" {
				message = ce.Error
			}
			if message == "" {
				message = "connection_error"
			}
			return nil, &appsync.UnauthorizedError{Message: message}
		case "ka":
			continue
		default:
			continue
		}
	}

subscribed:
	reqBody, err := json.Marshal(subscriptionRequest{
		Query:     onPublishPolicySubscription,
		Variables: map[string]any{},
	})
	if err != nil {
		return nil, err
	}
	startPayloadRaw, err := json.Marshal(subscriptionStartPayload{
		Data: string(reqBody),
		Extensions: subscriptionExtensions{
			Authorization: map[string]string{
				"Authorization":    c.RealtimeToken(),
				"host":             apiHost,
				"x-amz-user-agent": c.UserAgent(),
			},
		},
	})
	if err != nil {
		return nil, err
	}
	if err := writeWSJSON(conn, wsMessage{ID: "1", Type: "start", Payload: startPayloadRaw}); err != nil {
		return nil, err
	}

	for {
		msg, err := readWSMessage(ctx, conn)
		if err != nil {
			return nil, err
		}
		switch msg.Type {
		case "ka", "start_ack":
			continue
		case "connection_error":
			sendComplete(conn, msg.ID)
			return nil, &appsync.UnauthorizedError{Message: "connection_error"}
		case "error":
			sendComplete(conn, msg.ID)
			return nil, fmt.Errorf("onPublishPolicy subscription error: %s", string(msg.Payload))
		case "data":
			var frame onPublishDataFrame
			if err := json.Unmarshal(msg.Payload, &frame); err != nil {
				sendComplete(conn, msg.ID)
				return nil, &appsync.NetworkError{Op: "decode realtime payload", Err: err}
			}
			if frame.Data.OnPublishPolicy == nil {
				continue
			}
			p := flattenEntitlements(frame.Data.OnPublishPolicy.Policy)
			if len(p.Accounts) > 0 || len(p.Permissions) > 0 {
				sendComplete(conn, msg.ID)
				return p, nil
			}
		case "complete":
			return nil, &appsync.NetworkError{Op: "subscription complete", Err: fmt.Errorf("onPublishPolicy completed without usable data")}
		}
	}
}
