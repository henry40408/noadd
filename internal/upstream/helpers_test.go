package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// reply decides the answer to one request; nil means no answer.
type reply func(request *dns.Msg) *dns.Msg

func answerA(request *dns.Msg, ip string, ttl uint32) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	rr, err := dns.NewRR(request.Question[0].Name + " " + strconv.FormatUint(uint64(ttl), 10) + " IN A " + ip)
	if err != nil {
		panic(err)
	}
	response.Answer = append(response.Answer, rr)
	return response
}

func rcodeReply(request *dns.Msg, rcode int) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, rcode)
	response.RecursionAvailable = true
	return response
}

func queryFor(name string, qtype uint16) []byte {
	request := new(dns.Msg)
	request.SetQuestion(name, qtype)
	request.Id = 0x1234
	wire, err := request.Pack()
	if err != nil {
		panic(err)
	}
	return wire
}

// fakeUDP serves UDP on 127.0.0.1 and counts the datagrams it receives.
func fakeUDP(t *testing.T, handle reply) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	var received atomic.Int32
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			received.Add(1)
			request := new(dns.Msg)
			if request.Unpack(buffer[:n]) != nil {
				continue
			}
			response := handle(request)
			if response == nil {
				continue
			}
			if wire, err := response.Pack(); err == nil {
				_, _ = conn.WriteTo(wire, from)
			}
		}
	}()
	return conn.LocalAddr().String(), &received
}

// closedUDPAddr is a local UDP port nobody listens on: it fails fast with ICMP
// unreachable instead of waiting out a timeout.
func closedUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

// fakeDoT serves DNS over TLS for the name "localhost".
func fakeDoT(t *testing.T, handle reply) (addr string, connections *atomic.Int32, trust *tls.Config) {
	t.Helper()
	serverConfig := localhostTLSConfig(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig.server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go serveStream(conn, handle)
		}
	}()
	return listener.Addr().String(), &accepted, serverConfig.client
}

func serveStream(conn net.Conn, handle reply) {
	defer conn.Close()
	stream := &dns.Conn{Conn: conn}
	for {
		request, err := stream.ReadMsg()
		if err != nil {
			return
		}
		if response := handle(request); response != nil {
			if stream.WriteMsg(response) != nil {
				return
			}
		}
	}
}

type tlsPair struct{ server, client *tls.Config }

// localhostTLSConfig returns a server config and the client config trusting it.
func localhostTLSConfig(t *testing.T) tlsPair {
	t.Helper()
	probe := httptest.NewUnstartedServer(http.NotFoundHandler())
	probe.StartTLS()
	defer probe.Close()
	// httptest's certificate is valid for 127.0.0.1, example.com and localhost.
	pool := x509.NewCertPool()
	pool.AddCert(probe.Certificate())
	return tlsPair{
		server: &tls.Config{Certificates: probe.TLS.Certificates, MinVersion: tls.VersionTLS12},
		client: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
}

// fakeDoH serves DNS over HTTPS with HTTP/2.
func fakeDoH(t *testing.T, handle reply) (url string, requests *atomic.Int32, trust *tls.Config) {
	t.Helper()
	var count atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		body, _ := io.ReadAll(r.Body)
		request := new(dns.Msg)
		if r.Method != http.MethodPost || request.Unpack(body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		response := handle(request)
		if response == nil {
			http.Error(w, "no answer", http.StatusServiceUnavailable)
			return
		}
		wire, _ := response.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return server.Listener.Addr().String(), &count, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// staticResolver maps every host to one address.
type staticResolver struct{ addr netip.Addr }

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.addr}, nil
}

func newTestForwarder(t *testing.T, cfg Config) *Forwarder {
	t.Helper()
	if cfg.MinTimeout == 0 {
		cfg.MinTimeout = time.Millisecond
	}
	return New(context.Background(), cfg)
}
