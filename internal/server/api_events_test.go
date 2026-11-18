package server

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/events"
)

const eventWait = 5 * time.Second

// sseClient reads one /api/events connection.
type sseClient struct {
	t      testing.TB
	cancel context.CancelFunc
	frames chan string
	closed chan struct{}
}

type sseFrame struct{ name, data string }

func (h *apiHarness) openStream(baseURL, query string) *sseClient {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/events"+query, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("Cookie", "session="+h.token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		cancel()
		h.t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		cancel()
		h.t.Fatalf("status %d, content type %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	client := &sseClient{t: h.t, cancel: cancel, frames: make(chan string, 64), closed: make(chan struct{})}
	go func() {
		defer close(client.closed)
		defer response.Body.Close()
		scanner := bufio.NewScanner(response.Body)
		var frame strings.Builder
		for scanner.Scan() {
			if scanner.Text() == "" {
				client.frames <- frame.String()
				frame.Reset()
				continue
			}
			frame.WriteString(scanner.Text() + "\n")
		}
	}()
	h.t.Cleanup(cancel)
	return client
}

func (c *sseClient) next() sseFrame {
	c.t.Helper()
	select {
	case raw := <-c.frames:
		lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
		name, _ := strings.CutPrefix(lines[0], "event: ")
		data, _ := strings.CutPrefix(lines[len(lines)-1], "data: ")
		return sseFrame{name: name, data: data}
	case <-time.After(eventWait):
		c.t.Fatal("no event in time")
		return sseFrame{}
	}
}

func (c *sseClient) wantEvent(name string) sseFrame {
	c.t.Helper()
	frame := c.next()
	if frame.name != name {
		c.t.Fatalf("event %q (%s), want %q", frame.name, frame.data, name)
	}
	return frame
}

func TestEventStreamOpensWithRebuildStateThenSnapshot(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedRecentLogs()
	server := httptest.NewServer(h.handler)
	t.Cleanup(server.Close)

	client := h.openStream(server.URL, "?stats=1")
	rebuild := client.wantEvent("rebuild")
	if rebuild.data != `{"rebuilding":false,"started_at":0,"last_duration_ms":0}` {
		t.Fatalf("rebuild = %s", rebuild.data)
	}
	snapshot := client.wantEvent("stats")
	for _, key := range []string{`"summary":{`, `"timeline":[`, `"top_domains":[`, `"top_clients":[`, `"top_upstreams":[`} {
		if !strings.Contains(snapshot.data, key) {
			t.Errorf("snapshot lacks %s: %s", key, snapshot.data)
		}
	}
	if !strings.Contains(snapshot.data, `"total_today":11`) {
		t.Errorf("snapshot = %s", snapshot.data)
	}
}

func TestEventStreamWithoutStatsSendsOnlyRebuildThenPings(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := httptest.NewServer(h.handler)
	t.Cleanup(server.Close)

	client := h.openStream(server.URL, "")
	client.wantEvent("rebuild")
	h.eventually(func() bool { return h.deps.Events.ConnectionCount() == 1 })
	h.deps.Events.Send(&events.Tick{Seq: 7, At: 99, Traffic: true})
	if ping := client.wantEvent("ping"); ping.data != `{"at":99,"seq":7,"traffic":true}` {
		t.Fatalf("ping = %s", ping.data)
	}
	// A tick that carries a snapshot yields a second event.
	h.deps.Events.Send(&events.Tick{Seq: 8, At: 100, Snapshot: map[string]int{"x": 1}})
	client.wantEvent("ping")
	if stats := client.wantEvent("stats"); stats.data != `{"x":1}` {
		t.Fatalf("stats = %s", stats.data)
	}
}

func TestEventStreamForwardsLogsOnlyWhenAskedAndRebuildEdges(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := httptest.NewServer(h.handler)
	t.Cleanup(server.Close)

	client := h.openStream(server.URL, "?logs=true")
	client.wantEvent("rebuild")
	h.eventually(func() bool { return h.deps.Events.ConnectionCount() == 1 })
	// The subscription to the logger is made before the headers are sent, so
	// the first rebuild frame means it is live.
	h.deps.LogEvents.Log(db.QueryLogEntry{Timestamp: 1, Domain: "live.example.com", QueryType: "A", ClientIP: "10.0.0.1"})
	if entry := client.wantEvent("log"); !strings.Contains(entry.data, `"domain":"live.example.com"`) {
		t.Fatalf("log = %s", entry.data)
	}

	done := h.deps.Rebuild.Spawn(func() error { return nil })
	<-done
	client.wantEvent("rebuild")
	if edge := client.wantEvent("rebuild"); !strings.Contains(edge.data, `"rebuilding":false`) {
		t.Fatalf("closing edge = %s", edge.data)
	}

	quiet := h.openStream(server.URL, "")
	quiet.wantEvent("rebuild")
	h.deps.LogEvents.Log(db.QueryLogEntry{Timestamp: 2, Domain: "unseen.example.com", QueryType: "A", ClientIP: "10.0.0.1"})
	h.deps.Events.Send(&events.Tick{Seq: 1})
	if frame := quiet.next(); frame.name != "ping" {
		t.Fatalf("a client that did not ask for logs got %q", frame.name)
	}
}

func TestEventStreamEndsWhenTheClientDisconnects(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := httptest.NewServer(h.handler)
	t.Cleanup(server.Close)

	client := h.openStream(server.URL, "?stats=1&logs=1")
	client.wantEvent("rebuild")
	h.eventually(func() bool { return h.deps.Events.ConnectionCount() == 1 && h.deps.Events.WantsStats() })
	client.cancel()
	h.eventually(func() bool { return h.deps.Events.ConnectionCount() == 0 && !h.deps.Events.WantsStats() })
}

func TestEventStreamDoesNotBlockServerShutdown(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := httptest.NewUnstartedServer(h.handler)
	server.Config.RegisterOnShutdown(func() { close(h.stopStreams) })
	server.Start()
	t.Cleanup(server.Close)

	client := h.openStream(server.URL, "")
	client.wantEvent("rebuild")
	h.eventually(func() bool { return h.deps.Events.ConnectionCount() == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), eventWait)
	defer cancel()
	started := time.Now()
	if err := server.Config.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v (after %v)", err, time.Since(started))
	}
	<-client.closed
	if h.deps.Events.ConnectionCount() != 0 {
		t.Fatal("the stream's subscription outlived Shutdown")
	}
}

// deadlineRecorder is a ResponseWriter that records every write deadline.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	writes    int
}

func (d *deadlineRecorder) Write(body []byte) (int, error) {
	d.writes++
	if len(d.deadlines) != d.writes {
		return 0, errors.New("write without a fresh deadline")
	}
	return d.ResponseRecorder.Write(body)
}

func (d *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	d.deadlines = append(d.deadlines, deadline)
	return nil
}

func TestEventStreamSetsAWriteDeadlineBeforeEveryFrame(t *testing.T) {
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	stream := &eventStream{w: recorder, flush: http.NewResponseController(recorder)}
	for range 3 {
		if !stream.send("ping", pingEvent{}) {
			t.Fatal("send failed")
		}
	}
	if len(recorder.deadlines) != 3 {
		t.Fatalf("%d deadlines for 3 frames", len(recorder.deadlines))
	}
	for _, deadline := range recorder.deadlines {
		if time.Until(deadline) <= 0 || time.Until(deadline) > sseWriteTimeout {
			t.Fatalf("deadline %v not within the write timeout", deadline)
		}
	}
}
