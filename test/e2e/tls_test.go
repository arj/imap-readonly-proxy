//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

// TestUpstreamTLS checks certificate verification against Dovecot with
// a self-signed certificate (subjectAltName DNS:localhost).
func TestUpstreamTLS(t *testing.T) {
	tlsPort, certFile := os.Getenv("IRP_UPSTREAM_TLS_PORT"), os.Getenv("IRP_UPSTREAM_CERT")
	if tlsPort == "" || certFile == "" {
		t.Skip("IRP_UPSTREAM_TLS_PORT/IRP_UPSTREAM_CERT not set")
	}
	plainPort := strings.Split(upstreamAddr, ":")[1]
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	sum := sha256.Sum256(block.Bytes)
	pin := upstream.FormatFingerprint(sum[:])
	wrong := sha256.Sum256([]byte("other"))
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(localPass), bcrypt.MinCost)
	hash := string(hashBytes)

	// accountEndpoint loads a real configuration so that the config
	// parsing of the TLS options is covered as well.
	accountEndpoint := func(t *testing.T, extra string) upstream.Endpoint {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		body := fmt.Sprintf(`
[server]
listen = "127.0.0.1:0"
insecure_plaintext = true

[[accounts]]
local_user = "reader"
local_password_hash = %q
remote_host = "127.0.0.1"
remote_user = %q
remote_password = %q
%s
`, hash, upstreamUser, upstreamPass, extra)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Accounts[0].Endpoint()
	}

	tests := []struct {
		name, extra, wantErr string
	}{
		{"tls default rejects self-signed",
			fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\nremote_tls_server_name = \"localhost\"\n", tlsPort), "unknown authority"},
		{"starttls default rejects self-signed",
			fmt.Sprintf("remote_port = %s\nremote_security = \"starttls\"\nremote_tls_server_name = \"localhost\"\n", plainPort), "unknown authority"},
		{"ca file with matching server name",
			fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\nremote_ca_file = %q\nremote_tls_server_name = \"localhost\"\n", tlsPort, certFile), ""},
		{"ca file with wrong server name",
			fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\nremote_ca_file = %q\n", tlsPort, certFile), "127.0.0.1"},
		{"pin tls",
			fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\nremote_tls_cert_sha256 = %q\n", tlsPort, pin), ""},
		{"pin starttls (lower-case, no colons)",
			fmt.Sprintf("remote_port = %s\nremote_security = \"starttls\"\nremote_tls_cert_sha256 = %q\n", plainPort,
				strings.ToLower(strings.ReplaceAll(pin, ":", ""))), ""},
		{"wrong pin",
			fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\nremote_tls_cert_sha256 = %q\n", tlsPort,
				upstream.FormatFingerprint(wrong[:])), "does not match remote_tls_cert_sha256 (server presented " + pin + ")"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := upstream.Dial(context.Background(), accountEndpoint(t, tt.extra), upstreamUser, upstreamPass)
			if err == nil {
				c.Close()
			}
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}

	t.Run("probe reports the pin", func(t *testing.T) {
		ep := accountEndpoint(t, fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\n", tlsPort))
		info, err := upstream.ProbeCertificate(context.Background(), ep)
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(info.Chain[0].Raw)
		if upstream.FormatFingerprint(got[:]) != pin || info.VerifyErr == nil {
			t.Fatalf("probe: fingerprint %X, verify error %v", got, info.VerifyErr)
		}
	})

	t.Run("proxy session over pinned upstream", func(t *testing.T) {
		addr := startProxyWithUpstream(t, fmt.Sprintf("remote_port = %s\nremote_security = \"tls\"\nremote_tls_cert_sha256 = %q\n", tlsPort, pin))
		c := login(t, addr)
		if out := c.cmd("a2", "a2 EXAMINE INBOX\r\n"); !strings.Contains(out, "a2 OK") || !strings.Contains(out, "3 EXISTS") {
			t.Fatalf("EXAMINE over pinned upstream: %q", out)
		}
	})
}
