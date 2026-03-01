package resinfo

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/oschwald/maxminddb-golang"
)

type ResInfo struct {
	Next plugin.Handler

	mu sync.RWMutex
	rl map[string][]int64

	qminMu    sync.RWMutex
	qminCache map[string]int64

	Zone string
	Link string

	ASNv4Reader *maxminddb.Reader
	ASNv6Reader *maxminddb.Reader
}

type ASNRecord struct {
	ASN  uint `maxminddb:"asn"`
	Info struct {
		Name string `maxminddb:"name"`
	} `maxminddb:"info"`
	Organization struct {
		Country string `maxminddb:"country"`
	} `maxminddb:"organization"`
}

const TypeRESINFO = 261

func New() *ResInfo {
	ri := &ResInfo{
		rl:        make(map[string][]int64),
		qminCache: make(map[string]int64),
		Link:      "https://resinfo.net",
	}

	go func() {
		for {
			time.Sleep(1 * time.Minute)
			now := time.Now().Unix()
			ri.mu.Lock()
			for ip, t := range ri.rl {
				if len(t) == 0 || now-t[len(t)-1] > 60 { delete(ri.rl, ip) }
			}
			ri.mu.Unlock()
			ri.qminMu.Lock()
			for ip, last := range ri.qminCache {
				if now-last > 10 { delete(ri.qminCache, ip) }
			}
			ri.qminMu.Unlock()
		}
	}()
	return ri
}

func (ri *ResInfo) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	inZone := dns.IsSubDomain(ri.Zone, state.Name())
	isProperSubdomain := inZone && state.Name() != ri.Zone
	isFinalQuery := state.QType() == dns.TypeTXT || state.QType() == TypeRESINFO

	// 1. Passive QNAME Minimization Tracking (intermediate probes to any subdomain)
	if isProperSubdomain && !isFinalQuery {
		qtype := state.QType()
		if qtype == dns.TypeNS || qtype == dns.TypeA || qtype == dns.TypeAAAA || qtype == dns.TypeDS {
			ri.qminMu.Lock()
			ri.qminCache[state.IP()] = time.Now().Unix()
			ri.qminMu.Unlock()
		}

		// Return NODATA (NOERROR + SOA) to avoid SERVFAIL and allow resolver to continue
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Ns = []dns.RR{
			&dns.SOA{
				Hdr:     dns.RR_Header{Name: ri.Zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns1." + ri.Zone,
				Mbox:    "hostmaster." + ri.Zone,
				Serial:  uint32(time.Now().Unix()),
				Refresh: 7200,
				Retry:   3600,
				Expire:  1209600,
				Minttl:  60,
			},
		}
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// 2. Only serve RESINFO response for TXT/RESINFO queries within the zone.
	if !inZone || !isFinalQuery {
		return plugin.NextOrFailure(ri.Name(), ri.Next, ctx, w, r)
	}

	// Rate limiting
	remoteAddr := state.IP()
	now := time.Now().Unix()
	ri.mu.Lock()
	var valid []int64
	for _, t := range ri.rl[remoteAddr] { if now-t < 10 { valid = append(valid, t) } }
	if len(valid) >= 10 { ri.mu.Unlock(); return dns.RcodeRefused, nil }
	ri.rl[remoteAddr] = append(valid, now)
	ri.mu.Unlock()

	// Build Diagnostic Response
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	qmin := "NO"
	ri.qminMu.RLock()
	if last, exists := ri.qminCache[remoteAddr]; exists && now-last <= 10 { qmin = "YES" }
	ri.qminMu.RUnlock()

	header := dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}
	addTxt := func(s string) { m.Answer = append(m.Answer, &dns.TXT{Hdr: header, Txt: []string{s}}) }

	isIPv6 := net.ParseIP(remoteAddr).To4() == nil
	ip := net.ParseIP(remoteAddr)
	var asnNum uint
	var asnName, country string
	asnReader := ri.ASNv4Reader; if isIPv6 { asnReader = ri.ASNv6Reader }
	if asnReader != nil {
		var rec ASNRecord
		if err := asnReader.Lookup(ip, &rec); err == nil && rec.ASN != 0 {
			asnNum, asnName, country = rec.ASN, rec.Info.Name, rec.Organization.Country
		}
	}

	resolverLine := fmt.Sprintf("Resolver: %s", remoteAddr)
	if asnNum != 0 || country != "" {
		resolverLine += " ["
		if asnNum != 0 {
			resolverLine += fmt.Sprintf("AS%d %s", asnNum, asnName)
			if country != "" {
				resolverLine += ", "
			}
		}
		if country != "" {
			resolverLine += country
		}
		resolverLine += "]"
	}
	addTxt(resolverLine)
	addTxt(fmt.Sprintf("Transport: %s", state.Proto()))

	adFlag := r.AuthenticatedData
	cdFlag := r.CheckingDisabled

	opt := r.IsEdns0()
	do := false
	udpSize := uint16(512)
	cookie, padding, ecs := false, false, false
	if opt != nil {
		do = opt.Do()
		udpSize = opt.UDPSize()
		for _, o := range opt.Option {
			switch o.Option() {
			case dns.EDNS0COOKIE:
				cookie = true
			case dns.EDNS0PADDING:
				padding = true
			case dns.EDNS0SUBNET:
				ecs = true
			}
		}
	}

	addTxt(fmt.Sprintf("DNSSEC: DO=%s AD=%s CD=%s", boolYN(do), boolYN(adFlag), boolYN(cdFlag)))

	if cookie {
		addTxt("EDNS0-Cookie: YES")
	} else {
		addTxt("EDNS0-Cookie: NO")
	}
	if padding {
		addTxt("EDNS0-Padding: YES")
	} else {
		addTxt("EDNS0-Padding: NO")
	}
	if ecs {
		addTxt("EDNS0-Client-Subnet: YES")
	} else {
		addTxt("EDNS0-Client-Subnet: NO")
	}

	rand0x20 := hasUppercase(state.QName())
	if dns.CountLabel(state.Name()) == dns.CountLabel(ri.Zone)+3 {
		addTxt(fmt.Sprintf("QNAME-Minimization: %s", qmin))
	} else {
		addTxt("QNAME-Minimization: UNKNOWN (query check.my.dns.resinfo.net)")
	}
	addTxt(fmt.Sprintf("0x20-Case-Randomization: %s", boolYN(rand0x20)))
	addTxt(fmt.Sprintf("UDP-Buffer-Size: %d", udpSize))
	addTxt(fmt.Sprintf("Learn more: %s", ri.Link))

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func (ri *ResInfo) Name() string { return "resinfo" }

func hasUppercase(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

func boolYN(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}
