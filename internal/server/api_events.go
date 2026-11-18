package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/events"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/stats"
)

// sseKeepAliveInterval matches axum's default keep-alive.
const sseKeepAliveInterval = 15 * time.Second

// eventStream is one open /api/events connection.
type eventStream struct {
	w     http.ResponseWriter
	flush *http.ResponseController
}

// send writes one event and flushes it. A false return means the client is
// gone, so the handler must end.
func (s *eventStream) send(name string, payload any) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		// Nothing in these payloads can fail to marshal; skip rather than end.
		return true
	}
	return s.write(fmt.Sprintf("event: %s\ndata: %s\n\n", name, body))
}

func (s *eventStream) write(frame string) bool {
	if _, err := s.w.Write([]byte(frame)); err != nil {
		return false
	}
	return s.flush.Flush() == nil
}

// sseFlag accepts 1 as well as true.
func sseFlag(value string) bool { return value == "1" || value == "true" }

type pingEvent struct {
	At      int64  `json:"at"`
	Seq     uint64 `json:"seq"`
	Traffic bool   `json:"traffic"`
}

// streamEvents handles GET /api/events, the admin UI's one push channel, one
// connection per tab:
//
//   - ping every tick, the status indicator's heartbeat; it carries whether
//     any query was ever answered.
//   - stats, a dashboard snapshot, only when ?stats=1.
//   - log, one entry per answered query, only when ?logs=1.
//   - rebuild, on both edges of every filter rebuild, unasked for.
//
// On open a stats client gets a snapshot at once and every client gets the
// current rebuild state. The handler ends when the client goes away, when a
// write fails, or when the server starts shutting down; otherwise
// http.Server.Shutdown would wait on the stream forever.
func (a *api) streamEvents(w http.ResponseWriter, r *http.Request, _ authedUser) {
	query := r.URL.Query()
	wantsStats, wantsLogs := sseFlag(query.Get("stats")), sseFlag(query.Get("logs"))

	ticks := a.Events.Subscribe(wantsStats)
	defer ticks.Close()
	var logFeed <-chan *db.QueryLogEntry
	if wantsLogs && a.LogEvents != nil {
		subscription := a.LogEvents.Subscribe()
		defer subscription.Cancel()
		logFeed = subscription.C
	}
	rebuilds, stopRebuilds := a.Rebuild.Subscribe()
	defer stopRebuilds()

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	stream := &eventStream{w: w, flush: http.NewResponseController(w)}
	if !a.sendOpeningEvents(r.Context(), stream, wantsStats) {
		return
	}
	a.pumpEvents(r.Context(), stream, eventSources{ticks: ticks.C, logs: logFeed, rebuilds: rebuilds})
}

// sendOpeningEvents writes the rebuild state and, for a stats client, a
// snapshot, so server-rendered numbers do not lag the first tick.
func (a *api) sendOpeningEvents(ctx context.Context, stream *eventStream, wantsStats bool) bool {
	if !stream.send("rebuild", a.Rebuild.Status()) {
		return false
	}
	if !wantsStats {
		return true
	}
	snapshot, err := stats.ComputeSnapshot(ctx, a.DB, a.Now().Unix())
	if err != nil {
		a.log.Warn("failed to compute the opening dashboard snapshot",
			"event", "events.snapshot_failed", "stage", "initial", "error", err)
		return true
	}
	return stream.send("stats", snapshot)
}

type eventSources struct {
	ticks    <-chan *events.Tick
	logs     <-chan *db.QueryLogEntry
	rebuilds <-chan filter.Status
}

// pumpEvents forwards each source until the client or the server ends the
// stream. A closed source retires its own arm rather than ending the stream:
// the heartbeat must outlive the tail. The stream ends once all are retired.
func (a *api) pumpEvents(ctx context.Context, stream *eventStream, sources eventSources) {
	keepAlive := time.NewTicker(sseKeepAliveInterval)
	defer keepAlive.Stop()
	for sources.ticks != nil || sources.logs != nil {
		select {
		case <-ctx.Done():
			return
		case <-a.StopStreams:
			return
		case <-keepAlive.C:
			if !stream.write(":\n\n") {
				return
			}
		case tick, open := <-sources.ticks:
			if !open {
				sources.ticks = nil
				continue
			}
			if !sendTick(stream, tick) {
				return
			}
		case entry, open := <-sources.logs:
			if !open {
				sources.logs = nil
				continue
			}
			if !stream.send("log", entry) {
				return
			}
		case status := <-sources.rebuilds:
			if !stream.send("rebuild", status) {
				return
			}
		}
	}
}

func sendTick(stream *eventStream, tick *events.Tick) bool {
	if !stream.send("ping", pingEvent{At: tick.At, Seq: tick.Seq, Traffic: tick.Traffic}) {
		return false
	}
	if tick.Snapshot == nil {
		return true
	}
	return stream.send("stats", tick.Snapshot)
}
