package appsync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testData struct {
	Value string `json:"value"`
}

func newTestClient(server *httptest.Server) *Client {
	return New(server.URL, "https://example.com", "test-agent", "test-token")
}

func TestExecute_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify required headers are sent.
		if r.Header.Get("authorization") == "" {
			t.Error("missing authorization header")
		}
		if r.Header.Get("content-type") == "" {
			t.Error("missing content-type header")
		}
		if r.Header.Get("x-amz-user-agent") == "" {
			t.Error("missing x-amz-user-agent header")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"value": "hello"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	got, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Value != "hello" {
		t.Errorf("got %q, want %q", got.Value, "hello")
	}
}

func TestExecute_GraphQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{
				{"errorType": "SomeError", "message": "something went wrong"},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var unauth *UnauthorizedError
	if errors.As(err, &unauth) {
		t.Errorf("expected generic error, got UnauthorizedError: %v", err)
	}
	if err.Error() != "GraphQL SomeError: something went wrong" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestExecute_Unauthorized_GraphQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{
				{"errorType": "UnauthorizedException", "message": "token expired"},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var unauth *UnauthorizedError
	if !errors.As(err, &unauth) {
		t.Errorf("expected *UnauthorizedError, got %T: %v", err, err)
	}
}

func TestExecute_NetworkError_TypedAsNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	c := New(closedURL, "https://example.com", "test-agent", "test-token")
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Errorf("expected *NetworkError, got %T: %v", err, err)
	}
}

func TestExecute_HTTP500_TypedAsNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "kaboom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
	if netErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode: got %d, want %d", netErr.StatusCode, http.StatusInternalServerError)
	}
}

func TestExecute_HTTP500_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
	if netErr.Err == nil || netErr.Err.Error() != "empty body" {
		t.Errorf("expected wrapped err to be 'empty body', got %v", netErr.Err)
	}
}

func TestExecute_HTTP401_NotNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var unauth *UnauthorizedError
	if !errors.As(err, &unauth) {
		t.Errorf("expected *UnauthorizedError, got %T: %v", err, err)
	}
	var netErr *NetworkError
	if errors.As(err, &netErr) {
		t.Errorf("HTTP 401 must not be classified as *NetworkError")
	}
}

func TestExecute_DecodeError_TypedAsNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json {{{"))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := Execute[testData](context.Background(), c, "query { value }", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Errorf("expected *NetworkError for decode failure, got %T: %v", err, err)
	}
}
