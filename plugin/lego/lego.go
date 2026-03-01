package lego

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/miekg/dns"
)

var (
	challengesMu sync.RWMutex
	challenges   = make(map[string][]string)
	acmeOnce     sync.Once
)

type Lego struct {
	Next plugin.Handler

	Email   string
	ACMEDir string
	CertDir string
	Domain  string
}

func New() *Lego {
	return &Lego{
		ACMEDir: "https://acme-v02.api.letsencrypt.org/directory",
		CertDir: "/app/certs",
	}
}

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey { return u.key }

func (l *Lego) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	key := strings.ToLower(fqdn)
	challengesMu.Lock()
	challenges[key] = append(challenges[key], value)
	challengesMu.Unlock()
	return nil
}

func (l *Lego) CleanUp(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	key := strings.ToLower(fqdn)
	challengesMu.Lock()
	vals := challenges[key]
	filtered := vals[:0]
	for _, v := range vals {
		if v != value {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		delete(challenges, key)
	} else {
		challenges[key] = filtered
	}
	challengesMu.Unlock()
	return nil
}

func (l *Lego) EnsureCerts() error {
	if err := os.MkdirAll(l.CertDir, 0700); err != nil { return err }
	domain := strings.TrimSuffix(dns.Fqdn(l.Domain), ".")
	certPath := filepath.Join(l.CertDir, domain+".crt")
	keyPath := filepath.Join(l.CertDir, domain+".key")
	if _, err := os.Stat(certPath); err == nil { return nil }

	fmt.Printf("[lego] Generating placeholders for %s\n", domain)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{Organization: []string{"Lego Placeholder"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{domain, "*." + domain},
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certOut, _ := os.Create(certPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	b, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	keyOut.Close()
	return nil
}

func (l *Lego) OnStartup() error {
	acmeOnce.Do(func() {
		go func() {
			time.Sleep(5 * time.Second)
			domain := strings.TrimSuffix(dns.Fqdn(l.Domain), ".")
			privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			u := &User{Email: l.Email, key: privateKey}
			config := lego.NewConfig(u)
			config.CADirURL = l.ACMEDir
			client, err := lego.NewClient(config)
			if err != nil { return }
			reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil { return }
			u.Registration = reg
			// Use local nameserver and skip propagation check to break the loop
			client.Challenge.SetDNS01Provider(l,
				dns01.AddRecursiveNameservers([]string{"127.0.0.1:53"}),
				dns01.DisableCompletePropagationRequirement())
			request := certificate.ObtainRequest{Domains: []string{domain, "*." + domain}, Bundle: true}
			certs, err := client.Certificate.Obtain(request)
			if err != nil { fmt.Printf("[lego] ACME Error: %v\n", err); return }
			os.WriteFile(filepath.Join(l.CertDir, domain+".crt"), certs.Certificate, 0600)
			os.WriteFile(filepath.Join(l.CertDir, domain+".key"), certs.PrivateKey, 0600)
			fmt.Printf("[lego] Real certificates obtained for %s. Reloading...\n", domain)
			syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
		}()
	})
	return nil
}

func (l *Lego) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) == 0 { return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r) }

	qname := strings.ToLower(dns.Fqdn(r.Question[0].Name))
	if strings.Contains(qname, "_acme-challenge.") {
		challengesMu.RLock()
		tokens, exists := challenges[qname]
		challengesMu.RUnlock()

		fmt.Printf("[lego] Intercepted ACME query: %s %s (exists: %v)\n", dns.TypeToString[r.Question[0].Qtype], qname, exists)

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		if exists && r.Question[0].Qtype == dns.TypeTXT {
			for _, token := range tokens {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{token}})
			}
		} else if r.Question[0].Qtype == dns.TypeSOA {
			// Provide a virtual SOA for the challenge subdomain to satisfy cut checks
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: qname, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns1." + l.Domain,
				Mbox:    "admin." + l.Domain,
				Serial:  uint32(time.Now().Unix()),
				Refresh: 7200, Retry: 1800, Expire: 86400, Minttl: 60,
			})
		}
		
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
}

func (l *Lego) Name() string { return "lego" }
