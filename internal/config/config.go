// Package config loads and validates the proxy configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/bcrypt"

	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

// Config is the top-level configuration.
type Config struct {
	Server   Server    `toml:"server"`
	HTTP     HTTP      `toml:"http"`
	Accounts []Account `toml:"accounts"`
}

// HTTP configures the optional read-only REST API. It is disabled when
// Listen is empty.
type HTTP struct {
	// Enabled switches the REST endpoint on or off. If unset, the endpoint
	// is enabled when Listen is set.
	Enabled *bool  `toml:"enabled"`
	Listen  string `toml:"listen"`
	// TLSCert and TLSKey enable HTTPS. They may be the same files as
	// server.tls_cert/tls_key.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// InsecurePlaintext allows plain HTTP on a loopback address only.
	InsecurePlaintext bool `toml:"insecure_plaintext"`

	MaxConcurrentRequests      int   `toml:"max_concurrent_requests"`
	MaxConcurrentRequestsPerIP int   `toml:"max_concurrent_requests_per_ip"`
	MaxMessageBytes            int64 `toml:"max_message_bytes"`
}

// Enabled reports whether the REST API is configured.
func (h *HTTP) IsEnabled() bool { return switchedOn(h.Enabled, h.Listen) }

// IMAPEnabled reports whether the IMAP listener is configured.
func (s *Server) IMAPEnabled() bool { return switchedOn(s.Enabled, s.Listen) }

func switchedOn(enabled *bool, listen string) bool {
	if enabled != nil {
		return *enabled
	}
	return listen != ""
}

// Server configures the client-facing listener.
type Server struct {
	// Enabled switches the IMAP endpoint on or off. If unset, the endpoint
	// is enabled when Listen is set.
	Enabled *bool  `toml:"enabled"`
	Listen  string `toml:"listen"`
	// TLSCert and TLSKey enable implicit TLS (IMAPS) for clients.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// InsecurePlaintext allows a plaintext listener. It is only accepted
	// when Listen is a loopback address.
	InsecurePlaintext bool `toml:"insecure_plaintext"`

	MaxConnections      int `toml:"max_connections"`
	MaxConnectionsPerIP int `toml:"max_connections_per_ip"`
}

// Account maps one local login to one upstream mailbox.
type Account struct {
	LocalUser         string `toml:"local_user"`
	LocalPasswordHash string `toml:"local_password_hash"` // bcrypt; enables IMAP login
	// APITokenSHA256 is the hex SHA-256 of the REST API bearer token
	// (see "imap-readonly-proxy generate-token"); enables REST access.
	APITokenSHA256 string `toml:"api_token_sha256"`

	RemoteHost          string `toml:"remote_host"`
	RemotePort          int    `toml:"remote_port"`
	RemoteSecurity      string `toml:"remote_security"` // tls | starttls | insecure-plaintext
	RemoteTLSServerName string `toml:"remote_tls_server_name"`
	RemoteCAFile        string `toml:"remote_ca_file"`
	RemoteUser          string `toml:"remote_user"`
	RemotePassword      string `toml:"remote_password"`
	RemotePasswordFile  string `toml:"remote_password_file"`

	// AllowedFolders, if set, is the complete list of visible folders
	// (and their children). BlockedFolders hides folders instead. At most
	// one may be set; AllowedFolders is recommended.
	AllowedFolders []string `toml:"allowed_folders"`
	BlockedFolders []string `toml:"blocked_folders"`
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		return nil, fmt.Errorf("config: unknown keys: %v", undec)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &cfg, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateListener(section, listen, cert, key string, plaintext bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%s.listen: %w", section, err)
	}
	hasTLS := cert != "" || key != ""
	if hasTLS && (cert == "" || key == "") {
		return fmt.Errorf("%s.tls_cert and %s.tls_key must both be set", section, section)
	}
	if hasTLS && plaintext {
		return fmt.Errorf("%s.insecure_plaintext cannot be combined with TLS", section)
	}
	if !hasTLS {
		if !plaintext {
			return fmt.Errorf("%s: configure tls_cert/tls_key, or set insecure_plaintext = true for a loopback listener", section)
		}
		if !isLoopbackHost(host) {
			return fmt.Errorf("%s.insecure_plaintext requires a loopback listen address", section)
		}
	}
	return nil
}

func (c *Config) validate() error {
	s := &c.Server
	h := &c.HTTP
	if !s.IMAPEnabled() && !h.IsEnabled() {
		return errors.New("both endpoints are switched off: enable [server] (IMAP) and/or [http] (REST)")
	}
	if s.IMAPEnabled() && s.Listen == "" {
		return errors.New("server.enabled = true requires server.listen")
	}
	if h.IsEnabled() && h.Listen == "" {
		return errors.New("http.enabled = true requires http.listen")
	}
	if s.IMAPEnabled() {
		if err := validateListener("server", s.Listen, s.TLSCert, s.TLSKey, s.InsecurePlaintext); err != nil {
			return err
		}
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = 64
	}
	if s.MaxConnectionsPerIP == 0 {
		s.MaxConnectionsPerIP = 8
	}
	if s.MaxConnections < 0 || s.MaxConnectionsPerIP < 0 {
		return errors.New("server connection limits must be positive")
	}
	if h.IsEnabled() {
		if err := validateListener("http", h.Listen, h.TLSCert, h.TLSKey, h.InsecurePlaintext); err != nil {
			return err
		}
	}
	if h.MaxConcurrentRequests == 0 {
		h.MaxConcurrentRequests = 16
	}
	if h.MaxConcurrentRequestsPerIP == 0 {
		h.MaxConcurrentRequestsPerIP = 4
	}
	if h.MaxMessageBytes == 0 {
		h.MaxMessageBytes = 25 << 20
	}
	if h.MaxConcurrentRequests < 0 || h.MaxConcurrentRequestsPerIP < 0 || h.MaxMessageBytes < 0 || h.MaxMessageBytes > 1<<30 {
		return errors.New("http limits out of range")
	}

	if len(c.Accounts) == 0 {
		return errors.New("at least one [[accounts]] entry is required")
	}
	seen := map[string]bool{}
	for i := range c.Accounts {
		a := &c.Accounts[i]
		if err := a.validate(s.IMAPEnabled(), h.IsEnabled()); err != nil {
			return fmt.Errorf("accounts[%d] (%q): %w", i, a.LocalUser, err)
		}
		if seen[a.LocalUser] {
			return fmt.Errorf("duplicate local_user %q", a.LocalUser)
		}
		seen[a.LocalUser] = true
	}
	return nil
}

func (a *Account) validate(imapOn, httpOn bool) error {
	if a.LocalUser == "" {
		return errors.New("local_user is required")
	}
	if !(imapOn && a.LocalPasswordHash != "") && !(httpOn && a.APITokenSHA256 != "") {
		return errors.New("account cannot be used: set local_password_hash (IMAP endpoint) or api_token_sha256 (REST endpoint) for an enabled endpoint")
	}
	if a.LocalPasswordHash != "" {
		if _, err := bcrypt.Cost([]byte(a.LocalPasswordHash)); err != nil {
			return errors.New("local_password_hash must be a bcrypt hash (use: imap-readonly-proxy hash-password)")
		}
	}
	if a.APITokenSHA256 != "" {
		b, err := hex.DecodeString(a.APITokenSHA256)
		if err != nil || len(b) != sha256.Size {
			return errors.New("api_token_sha256 must be 64 hex characters (use: imap-readonly-proxy generate-token)")
		}
	}
	if a.RemoteHost == "" || a.RemoteUser == "" {
		return errors.New("remote_host and remote_user are required")
	}
	switch upstream.Security(a.RemoteSecurity) {
	case upstream.SecurityTLS:
		if a.RemotePort == 0 {
			a.RemotePort = 993
		}
	case upstream.SecurityStartTLS:
		if a.RemotePort == 0 {
			a.RemotePort = 143
		}
	case upstream.SecurityInsecurePlaintext:
		if !isLoopbackHost(a.RemoteHost) {
			return errors.New("remote_security = \"insecure-plaintext\" is only allowed for loopback hosts")
		}
		if a.RemotePort == 0 {
			a.RemotePort = 143
		}
	default:
		return errors.New("remote_security must be \"tls\", \"starttls\" or \"insecure-plaintext\"")
	}
	if a.RemotePort < 1 || a.RemotePort > 65535 {
		return errors.New("remote_port out of range")
	}
	if (a.RemotePassword == "") == (a.RemotePasswordFile == "") {
		return errors.New("exactly one of remote_password and remote_password_file is required")
	}
	if a.RemotePasswordFile != "" {
		b, err := os.ReadFile(a.RemotePasswordFile)
		if err != nil {
			return fmt.Errorf("remote_password_file: %w", err)
		}
		a.RemotePassword = strings.TrimRight(string(b), "\r\n")
		if a.RemotePassword == "" {
			return errors.New("remote_password_file is empty")
		}
	}
	if len(a.AllowedFolders) > 0 && len(a.BlockedFolders) > 0 {
		return errors.New("allowed_folders and blocked_folders are mutually exclusive")
	}
	for _, f := range append(append([]string{}, a.AllowedFolders...), a.BlockedFolders...) {
		if f == "" || strings.ContainsAny(f, "*%") {
			return fmt.Errorf("invalid folder entry %q (wildcards are not supported)", f)
		}
	}
	return nil
}

// Endpoint returns the upstream endpoint of the account.
func (a *Account) Endpoint() upstream.Endpoint {
	return upstream.Endpoint{
		Host:          a.RemoteHost,
		Port:          a.RemotePort,
		Security:      upstream.Security(a.RemoteSecurity),
		TLSServerName: a.RemoteTLSServerName,
		CAFile:        a.RemoteCAFile,
	}
}

// Lookup returns the account for a local user name, or nil.
func (c *Config) Lookup(user string) *Account {
	for i := range c.Accounts {
		if c.Accounts[i].LocalUser == user {
			return &c.Accounts[i]
		}
	}
	return nil
}

// FolderVisible reports whether a folder may be listed or opened.
//
// Matching fails closed: allowed_folders matches case-sensitively (except
// INBOX), so a case variant is hidden; blocked_folders matches
// case-insensitively, so a case variant is also hidden. A folder matches an
// entry if it equals the entry or is a child of it ("/" or "." delimiter).
func (a *Account) FolderVisible(name string) bool {
	if len(a.AllowedFolders) > 0 {
		for _, e := range a.AllowedFolders {
			if folderMatch(name, e, false) {
				return true
			}
		}
		return false
	}
	for _, e := range a.BlockedFolders {
		if folderMatch(name, e, true) {
			return false
		}
	}
	return true
}

// HasFolderFilter reports whether any folder restriction is configured.
func (a *Account) HasFolderFilter() bool {
	return len(a.AllowedFolders) > 0 || len(a.BlockedFolders) > 0
}

func folderMatch(name, entry string, foldAll bool) bool {
	n, e := normINBOX(name), normINBOX(entry)
	if foldAll {
		n, e = strings.ToUpper(n), strings.ToUpper(e)
	}
	if n == e {
		return true
	}
	return strings.HasPrefix(n, e+"/") || strings.HasPrefix(n, e+".")
}

func normINBOX(s string) string {
	if len(s) >= 5 && strings.EqualFold(s[:5], "INBOX") && (len(s) == 5 || s[5] == '/' || s[5] == '.') {
		return "INBOX" + s[5:]
	}
	return s
}
