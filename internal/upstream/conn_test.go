package upstream

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newCert creates a certificate. With parent == nil it is self-signed.
func newCert(t *testing.T, tmpl *x509.Certificate, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{der: der, cert: c, key: key}
}

func (c *testCert) pemFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (c *testCert) pin() []byte {
	s := sha256.Sum256(c.der)
	return s[:]
}

// fakeServer is a minimal IMAP server that serves implicit TLS or
// STARTTLS with the given chain and records whether LOGIN was received.
type fakeServer struct {
	addr     string
	loggedIn atomic.Bool
}

func startFake(t *testing.T, security Security, chain ...*testCert) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cert := tls.Certificate{PrivateKey: chain[0].key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.der)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	fs := &fakeServer{addr: ln.Addr().String()}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go fs.serve(nc, security, cfg)
		}
	}()
	return fs
}

func (fs *fakeServer) serve(nc net.Conn, security Security, cfg *tls.Config) {
	defer func() { nc.Close() }()
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	if security == SecurityTLS {
		nc = tls.Server(nc, cfg)
	}
	r := bufio.NewReader(nc)
	write := func(s string) { _, _ = nc.Write([]byte(s)) }
	write("* OK fake ready\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		tag, cmd, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		verb, _, _ := strings.Cut(strings.ToUpper(cmd), " ")
		switch verb {
		case "CAPABILITY":
			write("* CAPABILITY IMAP4rev1 STARTTLS\r\n" + tag + " OK done\r\n")
		case "STARTTLS":
			write(tag + " OK begin TLS\r\n")
			tc := tls.Server(nc, cfg)
			if tc.Handshake() != nil {
				return
			}
			nc, r = tc, bufio.NewReader(tc)
		case "LOGIN":
			fs.loggedIn.Store(true)
			write(tag + " OK logged in\r\n")
		case "LOGOUT":
			write("* BYE\r\n" + tag + " OK bye\r\n")
			return
		default:
			write(tag + " BAD unknown\r\n")
		}
	}
}

func (fs *fakeServer) endpoint(t *testing.T, security Security) Endpoint {
	host, port, _ := net.SplitHostPort(fs.addr)
	p, _ := net.LookupPort("tcp", port)
	return Endpoint{Host: host, Port: p, Security: security, TLSServerName: "imap.test"}
}

func dial(ep Endpoint) error {
	c, err := Dial(context.Background(), ep, "user", "secret")
	if err == nil {
		c.Close()
	}
	return err
}

func TestUpstreamCertificateVerification(t *testing.T) {
	withSAN := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "imap.test"}, DNSNames: []string{"imap.test"}}, nil)
	cnOnly := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "imap.test"}}, nil)
	expired := newCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "old"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
	}, nil)
	ca := newCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil)
	leaf := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "imap.test"}, DNSNames: []string{"imap.test"}}, ca)
	other := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "imap.test"}, DNSNames: []string{"imap.test"}}, nil)

	tests := []struct {
		name     string
		security Security
		chain    []*testCert
		setup    func(*Endpoint)
		wantErr  string // empty: login must succeed
	}{
		{"self-signed rejected by default", SecurityTLS, []*testCert{withSAN}, nil, "unknown authority"},
		{"self-signed rejected by default (starttls)", SecurityStartTLS, []*testCert{withSAN}, nil, "unknown authority"},
		{"self-signed accepted via ca file", SecurityTLS, []*testCert{withSAN},
			func(ep *Endpoint) { ep.CAFile = withSAN.pemFile(t) }, ""},
		{"ca file needs subjectAltName", SecurityTLS, []*testCert{cnOnly},
			func(ep *Endpoint) { ep.CAFile = cnOnly.pemFile(t) }, "legacy Common Name"},
		{"pin accepts self-signed", SecurityTLS, []*testCert{withSAN},
			func(ep *Endpoint) { ep.CertSHA256 = withSAN.pin() }, ""},
		{"pin accepts self-signed (starttls)", SecurityStartTLS, []*testCert{withSAN},
			func(ep *Endpoint) { ep.CertSHA256 = withSAN.pin() }, ""},
		{"pin accepts cert without subjectAltName", SecurityTLS, []*testCert{cnOnly},
			func(ep *Endpoint) { ep.CertSHA256 = cnOnly.pin() }, ""},
		{"pin accepts expired cert", SecurityTLS, []*testCert{expired},
			func(ep *Endpoint) { ep.CertSHA256 = expired.pin() }, ""},
		{"pin rejects other cert", SecurityTLS, []*testCert{other},
			func(ep *Endpoint) { ep.CertSHA256 = withSAN.pin() }, "does not match remote_tls_cert_sha256"},
		{"pin rejects other cert (starttls)", SecurityStartTLS, []*testCert{other},
			func(ep *Endpoint) { ep.CertSHA256 = withSAN.pin() }, "does not match remote_tls_cert_sha256"},
		{"pin of CA does not accept leaf", SecurityTLS, []*testCert{leaf, ca},
			func(ep *Endpoint) { ep.CertSHA256 = ca.pin() }, "does not match"},
		{"pin and ca file exclusive", SecurityTLS, []*testCert{withSAN},
			func(ep *Endpoint) { ep.CertSHA256, ep.CAFile = withSAN.pin(), withSAN.pemFile(t) }, "mutually exclusive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := startFake(t, tt.security, tt.chain...)
			ep := fs.endpoint(t, tt.security)
			if tt.setup != nil {
				tt.setup(&ep)
			}
			err := dial(ep)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr == "" && !fs.loggedIn.Load():
				t.Fatal("login not received")
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			case tt.wantErr != "" && fs.loggedIn.Load():
				t.Fatal("credentials were sent despite failed verification")
			}
		})
	}
}

func TestProbeCertificate(t *testing.T) {
	self := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "imap.test"}, DNSNames: []string{"imap.test"}}, nil)
	for _, sec := range []Security{SecurityTLS, SecurityStartTLS} {
		fs := startFake(t, sec, self)
		ep := fs.endpoint(t, sec)
		info, err := ProbeCertificate(context.Background(), ep)
		if err != nil {
			t.Fatalf("%s: %v", sec, err)
		}
		if len(info.Chain) != 1 || string(info.Chain[0].Raw) != string(self.der) {
			t.Fatalf("%s: wrong chain", sec)
		}
		if info.VerifyErr == nil {
			t.Fatalf("%s: self-signed certificate reported as trusted", sec)
		}
		if fs.loggedIn.Load() {
			t.Fatalf("%s: probe sent LOGIN", sec)
		}
		ep.CAFile = self.pemFile(t)
		if info, err = ProbeCertificate(context.Background(), ep); err != nil || info.VerifyErr != nil {
			t.Fatalf("%s with CA file: %v %v", sec, err, info.VerifyErr)
		}
	}
}

func TestFingerprintFormat(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	s := FormatFingerprint(sum[:])
	if len(s) != 95 || strings.ToUpper(s) != s {
		t.Fatalf("bad format %q", s)
	}
	for _, in := range []string{s, strings.ToLower(s), strings.ReplaceAll(s, ":", ""), " " + s + "\n"} {
		b, err := ParseFingerprint(in)
		if err != nil || string(b) != string(sum[:]) {
			t.Fatalf("parse %q: %v", in, err)
		}
	}
	for _, in := range []string{"", "AB", s + ":00", "zz" + s[2:]} {
		if _, err := ParseFingerprint(in); err == nil {
			t.Fatalf("parse %q succeeded", in)
		}
	}
}
