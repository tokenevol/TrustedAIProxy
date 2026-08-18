package gcpattestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const DefaultSocketPath = "/run/container_launcher/teeserver.sock"

type Client struct {
	audience string
	http     *http.Client
}

type tokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces"`
}

func New(socketPath, audience string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		audience: audience,
		http: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
	}
}

func (c *Client) Audience() string { return c.audience }

func (c *Client) Token(ctx context.Context, nonces []string) (string, error) {
	body, err := json.Marshal(tokenRequest{
		Audience:  c.audience,
		TokenType: "OIDC",
		Nonces:    nonces,
	})
	if err != nil {
		return "", fmt.Errorf("encode attestation token request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("request Confidential Space attestation token: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read attestation token: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Confidential Space launcher returned %s: %s", response.Status, strings.TrimSpace(string(responseBody)))
	}
	token := strings.TrimSpace(string(responseBody))
	if len(strings.Split(token, ".")) != 3 {
		return "", fmt.Errorf("Confidential Space launcher returned an invalid OIDC token")
	}
	return token, nil
}
