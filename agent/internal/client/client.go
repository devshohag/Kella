// Package client talks to the Kella cloud API. Outbound HTTPS only.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/devshohag/kella/agent/internal/model"
)

type Client struct {
	base  string
	token string
	http  *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		http:  &http.Client{Timeout: 45 * time.Second},
	}
}

func (c *Client) SetToken(t string) { c.token = t }

func (c *Client) Enroll(ctx context.Context, req model.EnrollRequest) (*model.EnrollResponse, error) {
	var out model.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/agent/enroll", req, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PutFacts(ctx context.Context, f model.Facts) error {
	return c.do(ctx, http.MethodPut, "/api/agent/facts", f, nil, false)
}

func (c *Client) SendEvents(ctx context.Context, b model.EventBatch) error {
	return c.do(ctx, http.MethodPost, "/api/agent/events", b, nil, true)
}

// PollCommands long-polls for up to waitSec seconds.
func (c *Client) PollCommands(ctx context.Context, waitSec int) ([]model.Command, error) {
	var out []model.Command
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/agent/commands?wait=%d", waitSec), nil, &out, false)
	return out, err
}

func (c *Client) Ack(ctx context.Context, id string, ack model.CommandAck) error {
	return c.do(ctx, http.MethodPost, "/api/agent/commands/"+id+"/ack", ack, nil, false)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, gz bool) error {
	var body io.Reader
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		if gz {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			_, _ = w.Write(raw)
			_ = w.Close()
			body = &buf
			req.Header.Set("Content-Encoding", "gzip")
		} else {
			body = bytes.NewReader(raw)
		}
		req.Body = io.NopCloser(body)
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", "kella-agent")

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("%s %s: status %d: %s", method, path, res.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil && res.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return nil
}
