package appsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// UnauthorizedError is returned when AppSync rejects the JWT (HTTP 401 or
// GraphQL UnauthorizedException errorType).
type UnauthorizedError struct{ Message string }

func (e *UnauthorizedError) Error() string { return "unauthorized: " + e.Message }

// NetworkError captures any transport-level failure: connection errors,
// body-read errors, non-2xx HTTP responses (other than 401, which is
// surfaced as UnauthorizedError), and malformed response bodies.
type NetworkError struct {
	Op         string // "request", "read body", "decode response"
	StatusCode int    // 0 if not from an HTTP response
	Err        error
}

func (e *NetworkError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("network error: %s: HTTP %d: %v", e.Op, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("network error: %s: %v", e.Op, e.Err)
}

func (e *NetworkError) Unwrap() error { return e.Err }

// Client sends GraphQL requests to AppSync authenticated by a JWT.
type Client struct {
	endpoint    string
	origin      string
	userAgent   string
	idToken     string
	accessToken string
	http        *http.Client
}

// Endpoint returns the configured AppSync GraphQL endpoint.
func (c *Client) Endpoint() string { return c.endpoint }

// IDToken returns the JWT used for AppSync authorization.
func (c *Client) IDToken() string { return c.idToken }

// UserAgent returns the Amplify user-agent string sent with AppSync requests.
func (c *Client) UserAgent() string { return c.userAgent }

// SetAccessToken stores the Cognito access token used for realtime WebSocket
// subscriptions (AppSync realtime requires the access token, not the ID token).
func (c *Client) SetAccessToken(t string) { c.accessToken = t }

// RealtimeToken returns the token for WebSocket auth: the access token when
// available, falling back to the ID token.
func (c *Client) RealtimeToken() string {
	if c.accessToken != "" {
		return c.accessToken
	}
	return c.idToken
}

// New creates a Client. origin is TEAM_FRONTEND_URL (used for Origin/Referer headers).
func New(endpoint, origin, userAgent, idToken string) *Client {
	return &Client{
		endpoint:  endpoint,
		origin:    origin,
		userAgent: userAgent,
		idToken:   idToken,
		http:      &http.Client{Timeout: 15 * time.Second},
	}
}

type gqlRequest struct {
	Query     string `json:"query"`
	Variables any    `json:"variables,omitempty"`
}

type gqlResponse[T any] struct {
	Data   T          `json:"data"`
	Errors []gqlError `json:"errors,omitempty"`
}

type gqlError struct {
	ErrorType string `json:"errorType"`
	Message   string `json:"message"`
}

// Execute runs a GraphQL operation against the AppSync endpoint and decodes
// the result into T. It returns UnauthorizedError for HTTP 401 responses and
// for GraphQL responses with errorType "UnauthorizedException".
func Execute[T any](ctx context.Context, c *Client, query string, vars any) (T, error) {
	var zero T
	body, err := json.Marshal(gqlRequest{Query: query, Variables: vars})
	if err != nil {
		return zero, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	req.Header.Set("authorization", c.idToken)
	req.Header.Set("content-type", "application/json; charset=UTF-8")
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("origin", c.origin)
	req.Header.Set("referer", c.origin+"/")
	req.Header.Set("x-amz-user-agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return zero, &NetworkError{Op: "request", Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, &NetworkError{Op: "read body", StatusCode: resp.StatusCode, Err: err}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return zero, &UnauthorizedError{Message: string(raw)}
	}
	if resp.StatusCode != http.StatusOK {
		bodyErr := errors.New(string(raw))
		if len(raw) == 0 {
			bodyErr = fmt.Errorf("empty body")
		}
		return zero, &NetworkError{Op: "request", StatusCode: resp.StatusCode, Err: bodyErr}
	}
	var out gqlResponse[T]
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, &NetworkError{Op: "decode response", StatusCode: resp.StatusCode, Err: err}
	}
	if len(out.Errors) > 0 {
		if out.Errors[0].ErrorType == "UnauthorizedException" {
			return zero, &UnauthorizedError{Message: out.Errors[0].Message}
		}
		return zero, fmt.Errorf("GraphQL %s: %s", out.Errors[0].ErrorType, out.Errors[0].Message)
	}
	return out.Data, nil
}
