package dnsserver

import (
	"context"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/db"
)

type discardLogger struct{}

func (discardLogger) Log(db.QueryLogEntry) bool { return true }

func benchmarkHandler(b *testing.B, upstreamAddr string) *Handler {
	b.Helper()
	handler := newTestHandler(b, handlerOptions{upstreamAddr: upstreamAddr, blocked: []string{blockedDomain}})
	handler.cfg.Logger = discardLogger{}
	return handler.Handler
}

func BenchmarkHandleCached(b *testing.B) {
	handler := benchmarkHandler(b, startUpstream(b, 0).addr)
	request := Request{Bytes: queryBytes(b, 1, "cached.example.com.", mdns.TypeA), ClientIP: localhost}
	if _, err := handler.Handle(context.Background(), request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := handler.Handle(context.Background(), request); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkHandleBlocked(b *testing.B) {
	handler := benchmarkHandler(b, "")
	request := Request{Bytes: queryBytes(b, 1, blockedDomain+".", mdns.TypeA), ClientIP: localhost}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := handler.Handle(context.Background(), request); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
