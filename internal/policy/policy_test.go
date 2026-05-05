package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drogers0/awsup/internal/appsync"
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
