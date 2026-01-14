/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DiscoveryDocument represents the OIDC discovery document structure
type DiscoveryDocument struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
}

// Client handles OIDC discovery document fetching
type Client struct {
	httpClient HTTPClient
}

// NewClientWithHTTPClient creates an OIDC client with a custom HTTP client
func NewClientWithHTTPClient(client HTTPClient) *Client {
	return &Client{httpClient: client}
}

// FetchDiscovery fetches the OIDC discovery document from the issuer URL
func (c *Client) FetchDiscovery(ctx context.Context, issuerURL string) (*DiscoveryDocument, error) {
	// Normalize issuer URL and build well-known URL
	wellKnownURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("token_endpoint not found in discovery document")
	}

	return &doc, nil
}
