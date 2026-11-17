package dnsserver

import (
	"context"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/querylog"
	"github.com/henry40408/noadd/internal/upstream"
)

// pipeline wires the real database, filter manager and query logger around a
// handler, as the server does.
func pipeline(t *testing.T, upstreamAddr string) (*Handler, *db.DB, *querylog.Logger, *filter.Manager) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, t.TempDir()+"/noadd.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(ctx) })

	manager := &filter.Manager{DB: database, Holder: filter.NewHolder(filter.New(filter.EngineInput{}))}
	logger := querylog.New(querylog.Config{Sink: database, FlushThreshold: 500, FlushInterval: time.Second, Logger: quietLogger()})
	go logger.Run(ctx)
	forwarder := upstream.New(ctx, upstream.Config{Servers: []string{upstreamAddr}, Logger: quietLogger()})
	handler := New(Config{
		Filter: manager.Holder, Cache: cache.New(cache.Config{CapacityBytes: 64 << 20}),
		Forwarder: forwarder, Logger: logger, Slog: quietLogger(),
	})
	t.Cleanup(handler.Close)
	return handler, database, logger, manager
}

// Rust: integration_test.rs test_full_query_pipeline_block
func TestFullQueryPipelineBlock(t *testing.T) {
	ctx := context.Background()
	handler, database, logger, manager := pipeline(t, "127.0.0.1:9")
	if _, err := database.AddCustomRule(ctx, "||ads.blocked.com^", "block"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	response, err := handler.Handle(ctx, Request{Bytes: queryBytes(t, 1234, "ads.blocked.com.", mdns.TypeA), ClientIP: mustAddr("192.168.1.100")})
	if err != nil {
		t.Fatal(err)
	}
	if answers := unpack(t, response.Bytes).Answer; len(answers) == 0 || answers[0].(*mdns.A).A.String() != "0.0.0.0" {
		t.Fatalf("answers = %v", answers)
	}
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	logs, err := database.QueryLogs(ctx, db.QueryLogFilter{}, 10, 0)
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs = %v, err %v", logs, err)
	}
	if logs[0].Domain != "ads.blocked.com" || !logs[0].Blocked || logs[0].ClientIP != "192.168.1.100" {
		t.Fatalf("log = %+v", logs[0])
	}
}

// Rust: test_full_query_pipeline_allow (a local upstream replaces the network)
func TestFullQueryPipelineAllow(t *testing.T) {
	ctx := context.Background()
	fake := startUpstream(t, 0)
	handler, database, logger, manager := pipeline(t, fake.addr)
	if err := manager.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	response, err := handler.Handle(ctx, Request{Bytes: queryBytes(t, 1, "example.com.", mdns.TypeA), ClientIP: localhost, DoHToken: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unpack(t, response.Bytes).Answer) == 0 {
		t.Fatal("an allowed domain should have the upstream's answers")
	}
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	logs, err := database.QueryLogs(ctx, db.QueryLogFilter{}, 10, 0)
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs = %v, err %v", logs, err)
	}
	log := logs[0]
	if log.Domain != "example.com" || log.Blocked || log.Cached || log.QueryType != "A" ||
		log.Upstream == nil || *log.Upstream != fake.addr || log.DohToken == nil || *log.DohToken != "phone" {
		t.Fatalf("log = %+v", log)
	}
}
