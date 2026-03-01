package resinfo

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// mockResponseWriter implements dns.ResponseWriter for testing.
type mockResponseWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func (m *mockResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (m *mockResponseWriter) RemoteAddr() net.Addr        { return m.remoteAddr }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error          { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)         {}
func (m *mockResponseWriter) Hijack()                     {}

func newMockWriter(ip string) *mockResponseWriter {
	return &mockResponseWriter{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 1234},
	}
}

func newRequest(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func TestQMINDetected(t *testing.T) {
	ri := New()
	ri.Zone = "resinfo.net."

	ctx := context.Background()
	ip := "1.2.3.4"
	w := newMockWriter(ip)

	// Send an intermediate query (a.b.c.resinfo.net. NS) — simulates QNAME minimization probe.
	intermediateReq := newRequest("a.b.c.resinfo.net.", dns.TypeNS)
	ri.ServeDNS(ctx, newMockWriter(ip), intermediateReq)

	// Send the actual test query (a.b.c.resinfo.net. TXT).
	testReq := newRequest("a.b.c.resinfo.net.", dns.TypeTXT)
	ri.ServeDNS(ctx, w, testReq)

	if w.msg == nil {
		t.Fatal("expected a response, got nil")
	}

	for _, rr := range w.msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if s == "QNAME-Minimization: YES" {
					return
				}
			}
		}
	}
	t.Error("expected 'QNAME-Minimization: YES' in response, not found")
}

func TestQMINNotDetected(t *testing.T) {
	ri := New()
	ri.Zone = "resinfo.net."

	ctx := context.Background()
	ip := "5.6.7.8"
	w := newMockWriter(ip)

	// Send the test query with no prior intermediate — non-minimizing resolver.
	testReq := newRequest("a.b.c.resinfo.net.", dns.TypeTXT)
	ri.ServeDNS(ctx, w, testReq)

	if w.msg == nil {
		t.Fatal("expected a response, got nil")
	}

	for _, rr := range w.msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if strings.HasPrefix(s, "QNAME-Minimization:") && !strings.Contains(s, "YES") {
					return
				}
			}
		}
	}
	t.Error("expected 'QNAME-Minimization: NO' in response, not found")
}
