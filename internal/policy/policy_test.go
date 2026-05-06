package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drogers0/awsup/internal/appsync"
	"github.com/gorilla/websocket"
)

func newTestClient(srv *httptest.Server) *appsync.Client {
	return appsync.New(srv.URL, "https://example.com", "test-agent", "test-token")
}

func TestGet_WithPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"getUserPolicy": map[string]any{
					"id":       "policy-1",
					"username": "idc_user@example.com",
					"policy": map[string]any{
						"accounts": []map[string]any{
							{"name": "prod", "id": "123456789012", "__typename": "Account"},
						},
						"permissions": []map[string]any{
							{"name": "ReadOnly", "id": "arn:aws:sso:::permissionSet/ssoins/ps-abc", "__typename": "Permission"},
						},
						"approvalRequired": true,
						"duration":         8,
						"__typename":       "Policy",
					},
					"__typename": "UserPolicy",
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	up, err := Get(context.Background(), c, "u1", []string{"g1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if up.ID != "policy-1" {
		t.Errorf("ID: got %q, want %q", up.ID, "policy-1")
	}
	if up.Username != "idc_user@example.com" {
		t.Errorf("Username: got %q", up.Username)
	}
	if up.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if len(up.Policy.Accounts) != 1 || up.Policy.Accounts[0].Name != "prod" {
		t.Errorf("Accounts: got %+v", up.Policy.Accounts)
	}
	if len(up.Policy.Permissions) != 1 || up.Policy.Permissions[0].Name != "ReadOnly" {
		t.Errorf("Permissions: got %+v", up.Policy.Permissions)
	}
	if !up.Policy.ApprovalRequired {
		t.Error("ApprovalRequired should be true")
	}
	if up.Policy.Duration != 8 {
		t.Errorf("Duration: got %d, want 8", up.Policy.Duration)
	}
}

func TestGet_NullPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"getUserPolicy": map[string]any{
					"id":         "direct-user-1",
					"username":   "idc_direct@example.com",
					"policy":     nil,
					"__typename": "UserPolicy",
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	up, err := Get(context.Background(), c, "u2", nil)
	if err != nil {
		t.Fatalf("unexpected error for null policy: %v", err)
	}
	if up == nil {
		t.Fatal("expected non-nil UserPolicy")
	}
	if up.Policy != nil {
		t.Errorf("expected nil Policy for direct-grant user, got %+v", up.Policy)
	}
	if up.ID != "direct-user-1" {
		t.Errorf("ID: got %q", up.ID)
	}
}

func TestGet_GraphQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{
				{"errorType": "AccessDenied", "message": "not authorized to view policy"},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Get(context.Background(), c, "u3", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not authorized to view policy") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func withTestDialer(t *testing.T, wsURL string) {
	t.Helper()
	orig := wsDialContext
	wsDialContext = func(ctx context.Context, _ string, _ []string) (*websocket.Conn, *http.Response, error) {
		dialer := websocket.Dialer{Subprotocols: []string{"graphql-ws"}}
		return dialer.DialContext(ctx, wsURL, nil)
	}
	t.Cleanup(func() { wsDialContext = orig })
}

func newRealtimeServer(t *testing.T, h func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{Subprotocols: []string{"graphql-ws"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade failed: %v", err)
		}
		defer conn.Close()
		h(conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func realtimeClient() *appsync.Client {
	return appsync.New("https://abc123.appsync-api.us-east-1.amazonaws.com/graphql", "https://example.com", "ua", "token")
}

func TestGetOnPublishPolicyEntitlements_Success(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{ID: "1", Type: "data", Payload: mustRaw(t, map[string]any{
			"data": map[string]any{
				"onPublishPolicy": map[string]any{
					"id": "p1", "username": "u@test.com",
					"policy": []map[string]any{{
						"accounts":    []map[string]any{{"id": "123", "name": "Prod"}},
						"permissions": []map[string]any{{"id": "arn:perm", "name": "ReadOnly"}},
					}},
				},
			},
		})})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", []string{"g1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Accounts) != 1 || len(p.Permissions) != 1 {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestGetOnPublishPolicyEntitlements_Partial(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{ID: "1", Type: "data", Payload: mustRaw(t, map[string]any{
			"data": map[string]any{
				"onPublishPolicy": map[string]any{
					"id": "p1", "username": "u@test.com",
					"policy": []map[string]any{{
						"accounts": []map[string]any{{"id": "123", "name": "Prod"}},
					}},
				},
			},
		})})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Accounts) != 1 {
		t.Fatalf("expected account from partial payload")
	}
	if p.Permissions == nil || len(p.Permissions) != 0 {
		t.Fatalf("expected empty permission slice, got %+v", p.Permissions)
	}
}

func TestGetOnPublishPolicyEntitlements_PartialPermissionsOnly(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{ID: "1", Type: "data", Payload: mustRaw(t, map[string]any{
			"data": map[string]any{
				"onPublishPolicy": map[string]any{
					"id": "p1", "username": "u@test.com",
					"policy": []map[string]any{{
						"permissions": []map[string]any{{"id": "arn:perm", "name": "ReadOnly"}},
					}},
				},
			},
		})})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Accounts == nil || len(p.Accounts) != 0 {
		t.Fatalf("expected empty accounts slice, got %+v", p.Accounts)
	}
	if len(p.Permissions) != 1 {
		t.Fatalf("expected permissions from partial payload, got %+v", p.Permissions)
	}
}

func TestGetOnPublishPolicyEntitlements_EmptyThenUsable(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{ID: "1", Type: "data", Payload: mustRaw(t, map[string]any{
			"data": map[string]any{"onPublishPolicy": map[string]any{
				"id": "p1", "username": "u@test.com",
				"policy": []map[string]any{{"accounts": []any{}, "permissions": []any{}}},
			}},
		})})
		_ = conn.WriteJSON(wsMessage{ID: "1", Type: "data", Payload: mustRaw(t, map[string]any{
			"data": map[string]any{"onPublishPolicy": map[string]any{
				"id": "p1", "username": "u@test.com",
				"policy": []map[string]any{{"permissions": []map[string]any{{"id": "arn:perm", "name": "ReadOnly"}}}},
			}},
		})})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Permissions) != 1 {
		t.Fatalf("expected second usable frame, got %+v", p)
	}
}

func TestGetOnPublishPolicyEntitlements_Timeout(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		for {
			_ = conn.WriteJSON(wsMessage{Type: "ka"})
			time.Sleep(50 * time.Millisecond)
		}
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestGetOnPublishPolicyEntitlements_Unauthorized(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_error", Payload: mustRaw(t, map[string]any{"message": "unauthorized"})})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	var unauth *appsync.UnauthorizedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}

func TestGetOnPublishPolicyEntitlements_SubscriptionError(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "error", Payload: mustRaw(t, map[string]any{"message": "subscription failed"})})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	if err == nil || !strings.Contains(err.Error(), "subscription error") {
		t.Fatalf("expected subscription error, got %v", err)
	}
}

func TestGetOnPublishPolicyEntitlements_CompleteWithoutData(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{ID: "1", Type: "complete"})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	var netErr *appsync.NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected network error for complete without data, got %v", err)
	}
}

func TestGetOnPublishPolicyEntitlements_MalformedPayload(t *testing.T) {
	srv := newRealtimeServer(t, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "connection_ack"})
		_, _, _ = conn.ReadMessage()
		_ = conn.WriteJSON(wsMessage{Type: "data", Payload: json.RawMessage(`{"data":`)})
	})
	withTestDialer(t, "ws"+strings.TrimPrefix(srv.URL, "http"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := GetOnPublishPolicyEntitlements(ctx, realtimeClient(), "u1", nil)
	var netErr *appsync.NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected network error, got %v", err)
	}
}

func TestGetOnPublishPolicyEntitlements_InvalidEndpoint(t *testing.T) {
	client := appsync.New("http://localhost/graphql", "https://example.com", "ua", "token")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := GetOnPublishPolicyEntitlements(ctx, client, "u1", nil)
	var netErr *appsync.NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected network error, got %v", err)
	}
}
