package httpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client wraps http.Client for reuse.
type Client struct {
	HTTP *http.Client
}

// New creates a client with default timeout.
func New(timeout time.Duration) *Client {
	return &Client{HTTP: &http.Client{Timeout: timeout}}
}

// DoJSON executes request and decodes JSON if v is non-nil.
func (c *Client) DoJSON(ctx context.Context, method, urlStr string, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	if v == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// IsTimeout returns true if error is timeout-like.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// IsTLSError checks if error looks like TLS/x509 issue.
func IsTLSError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return containsAny(msg, []string{"tls", "TLS", "SSL", "x509", "certificate"})
}

func containsAny(msg string, parts []string) bool {
	for _, p := range parts {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
