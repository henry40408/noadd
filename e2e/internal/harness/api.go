package harness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// AdminUsername is the operator the suite creates and signs in as.
	AdminUsername = "testuser"
	// AdminPassword clears the minimum length and matches the Gherkin.
	AdminPassword = "correct horse battery staple"
	// SessionCookie is the name of the session cookie noadd sets over plain HTTP.
	SessionCookie = "session"
)

// API is the HTTP client the suite uses outside the browser. Its POSTs pass
// the CSRF guard because a request with neither Sec-Fetch-Site nor Origin
// counts as a non-browser caller.
type API struct {
	server *Server
	client *http.Client
}

// NewAPI binds a client to one instance.
func NewAPI(server *Server) *API {
	return &API{server: server, client: &http.Client{Timeout: 30 * time.Second}}
}

// NeedsSetup reports whether the instance still waits for its first operator.
func (a *API) NeedsSetup() (bool, error) {
	response, err := a.client.Get(a.server.BaseURL + "/api/health")
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()
	var health struct {
		NeedsSetup bool `json:"needs_setup"`
	}
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
		return false, fmt.Errorf("decoding /api/health: %w", err)
	}
	return health.NeedsSetup, nil
}

// Setup creates the first operator. A 409 (one exists) counts as success.
func (a *API) Setup(username, password string) error {
	response, err := a.postJSON("/api/auth/setup", map[string]string{
		"username":    username,
		"password":    password,
		"setup_token": a.server.SetupToken(),
	})
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusConflict {
		return nil
	}
	return fmt.Errorf("POST /api/auth/setup answered %d", response.StatusCode)
}

// Login signs in and returns the session cookie's value, which a scenario
// replays into the browser instead of spending the login rate limit.
func (a *API) Login(username, password string) (string, error) {
	response, err := a.postJSON("/api/auth/login", map[string]string{"username": username, "password": password})
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login answered %d", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == SessionCookie {
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("no %q cookie in the login response", SessionCookie)
}

// Provision creates the operator and signs in, returning the session token.
func (a *API) Provision() (string, error) {
	if err := a.Setup(AdminUsername, AdminPassword); err != nil {
		return "", err
	}
	return a.Login(AdminUsername, AdminPassword)
}

func (a *API) postJSON(path string, body any) (*http.Response, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, a.server.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return a.client.Do(request)
}

// GetJSON fetches an endpoint that answers a JSON object.
func (a *API) GetJSON(session, path string) (map[string]any, error) {
	decoded, err := a.GetJSONValue(session, path)
	if err != nil {
		return nil, err
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s did not answer a JSON object", path)
	}
	return object, nil
}

// GetJSONValue fetches an endpoint whose JSON may be an array or an object.
func (a *API) GetJSONValue(session, path string) (any, error) {
	request, err := a.authedGet(context.Background(), session, path)
	if err != nil {
		return nil, err
	}
	response, err := a.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s answered %d", path, response.StatusCode)
	}
	var decoded any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return decoded, nil
}

func (a *API) authedGet(ctx context.Context, session, path string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.server.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: session})
	return request, nil
}

// WaitUntilRebuilt blocks until no filter rebuild is in flight. Rebuild state
// is published only on GET /api/events; every connection opens with a rebuild
// event, so a rebuild that already finished reports as settled at once.
func (a *API) WaitUntilRebuilt(session string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := a.authedGet(ctx, session, "/api/events")
	if err != nil {
		return err
	}
	// The stream never ends, so the shared client's overall timeout must not apply.
	response, err := (&http.Client{}).Do(request)
	if err != nil {
		return fmt.Errorf("GET /api/events: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /api/events answered %d", response.StatusCode)
	}
	settled, err := readUntilRebuildSettled(response.Body)
	if err != nil {
		return fmt.Errorf("no settled rebuild event within %v: %w", timeout, err)
	}
	if !settled {
		return fmt.Errorf("/api/events closed before reporting a settled rebuild")
	}
	return nil
}

// readUntilRebuildSettled reads SSE frames, which end at a blank line, until a
// rebuild event says nothing is in flight.
func readUntilRebuildSettled(stream io.Reader) (bool, error) {
	var event string
	lines := bufio.NewScanner(stream)
	for lines.Scan() {
		line := lines.Text()
		switch {
		case line == "":
			event = ""
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:") && event == "rebuild":
			var data struct {
				Rebuilding *bool `json:"rebuilding"`
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if json.Unmarshal([]byte(payload), &data) == nil && data.Rebuilding != nil && !*data.Rebuilding {
				return true, nil
			}
		}
	}
	return false, lines.Err()
}
