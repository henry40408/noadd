package dnsserver

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/henry40408/noadd/internal/dns"
)

// respond answers a query for a listener. It always returns bytes: SERVFAIL
// when the pipeline fails or panics, so one bad packet costs one answer, not
// the process. In-flight queries ignore ctx cancellation so a shutdown lets
// them finish; the forwarder's timeouts bound them.
func (h *Handler) respond(ctx context.Context, request Request, transport string, client netip.AddrPort) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			h.log.Error("query handler panicked; answering SERVFAIL", "event", "dns.handler_panicked",
				"transport", transport, "client", client, "panic", fmt.Sprint(recovered))
			response = dns.BuildServfail(request.Bytes)
		}
	}()
	outcome, err := h.Handle(context.WithoutCancel(ctx), request)
	if err != nil {
		h.log.Debug("query handler failed; answering SERVFAIL", "event", "dns.handler_failed",
			"transport", transport, "client", client, "error", err)
		return dns.BuildServfail(request.Bytes)
	}
	return outcome.Bytes
}
