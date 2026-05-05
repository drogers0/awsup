package settings_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/drogers0/awsup/internal/appsync"
	"github.com/drogers0/awsup/internal/settings"
)

func TestGet_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"getSettings": map[string]any{
					"id":                        "settings",
					"duration":                  "8",
					"expiry":                    "30",
					"comments":                  true,
					"ticketNo":                  true,
					"approval":                  true,
					"modifiedBy":                "admin",
					"sesNotificationsEnabled":   false,
					"snsNotificationsEnabled":   false,
					"slackNotificationsEnabled": false,
					"teamAdminGroup":            "admin-group",
					"teamAuditorGroup":          "auditor-group",
					"useOUCache":                false,
					"createdAt":                 "2024-01-01T00:00:00Z",
					"updatedAt":                 "2024-01-02T00:00:00Z",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := appsync.New(srv.URL, "https://example.com", "test-agent", "test-token")
	s, err := settings.Get(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Duration != "8" {
		t.Errorf("Duration = %q, want %q", s.Duration, "8")
	}
	if !s.TicketNo {
		t.Errorf("TicketNo should be true")
	}
	if s.Expiry != "30" {
		t.Errorf("Expiry = %q, want %q", s.Expiry, "30")
	}
	if !s.Approval {
		t.Errorf("Approval should be true")
	}
}

func TestGet_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"errors": []map[string]any{
				{
					"errorType": "SomeError",
					"message":   "settings not found",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := appsync.New(srv.URL, "https://example.com", "test-agent", "test-token")
	_, err := settings.Get(context.Background(), c)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGet_NullResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"getSettings": nil,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := appsync.New(srv.URL, "https://example.com", "test-agent", "test-token")
	_, err := settings.Get(context.Background(), c)
	if err == nil {
		t.Fatal("expected error for null getSettings, got nil")
	}
}
