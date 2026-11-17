// Package registry reads the AdGuard hostlists registry.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultURL is the public registry.
const DefaultURL = "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json"

const requestTimeout = 30 * time.Second

// Filter is one list in the registry. The JSON names are the ones the admin
// API sends to the browser.
type Filter struct {
	FilterID    int64   `json:"filterId"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Homepage    *string `json:"homepage"`
	DownloadURL string  `json:"downloadUrl"`
	GroupID     int64   `json:"groupId"`
	Deprecated  bool    `json:"deprecated"`
	TimeUpdated string  `json:"timeUpdated"`
}

// Group is a category of lists.
type Group struct {
	GroupID   int64  `json:"groupId"`
	GroupName string `json:"groupName"`
}

// Data is the part of the registry the app uses.
type Data struct {
	Filters []Filter `json:"filters"`
	Groups  []Group  `json:"groups"`
}

// Client fetches the registry and caches the result. Callers must not modify
// the returned Data, because the cache shares it.
type Client struct {
	http      *http.Client
	url       string
	ttl       time.Duration
	userAgent string

	mu        sync.Mutex
	fetchedAt time.Time
	cached    *Data
}

// NewClient returns a client for url that reuses a result for ttl.
func NewClient(url string, ttl time.Duration, userAgent string) *Client {
	return &Client{http: &http.Client{Timeout: requestTimeout}, url: url, ttl: ttl, userAgent: userAgent}
}

// List returns the registry, from the cache while it is fresh.
func (c *Client) List(ctx context.Context) (Data, error) {
	if data, ok := c.fresh(); ok {
		return data, nil
	}
	data, err := c.fetch(ctx)
	if err != nil {
		return Data{}, err
	}
	c.mu.Lock()
	c.cached, c.fetchedAt = &data, time.Now()
	c.mu.Unlock()
	return data, nil
}

func (c *Client) fresh() (Data, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached == nil || time.Since(c.fetchedAt) >= c.ttl {
		return Data{}, false
	}
	return *c.cached, true
}

func (c *Client) fetch(ctx context.Context) (Data, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return Data{}, fmt.Errorf("http error: %w", err)
	}
	request.Header.Set("User-Agent", c.userAgent)
	response, err := c.http.Do(request)
	if err != nil {
		return Data{}, fmt.Errorf("http error: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 400 {
		return Data{}, fmt.Errorf("http error: HTTP status %s for url (%s)", response.Status, c.url)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Data{}, fmt.Errorf("http error: %w", err)
	}
	var data Data
	if err := json.Unmarshal(body, &data); err != nil {
		return Data{}, fmt.Errorf("parse error: %w", err)
	}
	return data, nil
}
