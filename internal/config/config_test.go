package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cost-4 bcrypt hash of "pw", for tests only.
const testHash = "$2a$04$lRBsmIgso90UGpkjdx9rDuZRilQlAR9xCbuZGX5codV76xK6pwu.2"

func load(t *testing.T, body string) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	return err
}

const account = `
[[accounts]]
local_user = "u"
local_password_hash = "` + testHash + `"
remote_host = "imap.example.org"
remote_security = "tls"
remote_user = "r"
remote_password = "x"
`

func TestValidation(t *testing.T) {
	tests := []struct {
		name, body, wantErr string
	}{
		{"loopback plaintext ok", "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\n" + account, ""},
		{"plaintext on all interfaces", "[server]\nlisten = \":1143\"\ninsecure_plaintext = true\n" + account, "loopback"},
		{"no tls no plaintext", "[server]\nlisten = \"127.0.0.1:1143\"\n" + account, "tls_cert"},
		{"unknown key", "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\nwritable = true\n" + account, "unknown keys"},
		{"plain bcrypt missing", "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\n" +
			strings.Replace(account, testHash, "pw", 1), "bcrypt"},
		{"remote plaintext non-loopback", "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\n" +
			strings.Replace(account, `"tls"`, `"insecure-plaintext"`, 1), "loopback"},
		{"wildcard folder", "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\n" + account +
			"allowed_folders = [\"*\"]\n", "wildcards"},
		{"both filters", "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\n" + account +
			"allowed_folders = [\"INBOX\"]\nblocked_folders = [\"Secret\"]\n", "mutually exclusive"},
	}
	for _, tt := range tests {
		err := load(t, tt.body)
		switch {
		case tt.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tt.name, err)
		case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
			t.Errorf("%s: want error containing %q, got %v", tt.name, tt.wantErr, err)
		}
	}
}

func TestFolderVisible(t *testing.T) {
	allow := &Account{AllowedFolders: []string{"INBOX", "Projects"}}
	for name, want := range map[string]bool{
		"INBOX": true, "inbox": true, "INBOX/Sub": true, "Projects": true, "Projects.A": true,
		"projects": false, "ProjectsX": false, "Secret": false, "": false,
	} {
		if got := allow.FolderVisible(name); got != want {
			t.Errorf("allow %q = %v, want %v", name, got, want)
		}
	}
	block := &Account{BlockedFolders: []string{"Secret"}}
	for name, want := range map[string]bool{
		"INBOX": true, "Secret": false, "SECRET": false, "secret/x": false, "SecretX": true,
	} {
		if got := block.FolderVisible(name); got != want {
			t.Errorf("block %q = %v, want %v", name, got, want)
		}
	}
}

const tokenHash = "aa0e0ab2e7bb4c1b8d2c2c6a3df4d3a4d0b8e4f2b4c8f0e6a1b2c3d4e5f60718"

func loadCfg(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestEndpointSwitches(t *testing.T) {
	imap := "[server]\nlisten = \"127.0.0.1:1143\"\ninsecure_plaintext = true\n"
	rest := "[http]\nlisten = \"127.0.0.1:8080\"\ninsecure_plaintext = true\n"
	both := account + "api_token_sha256 = \"" + tokenHash + "\"\n"
	tokenOnly := strings.Replace(both, "local_password_hash = \""+testHash+"\"\n", "", 1)
	tests := []struct {
		name           string
		body           string
		imapOn, httpOn bool
		wantErr        string
	}{
		{"imap only (implicit)", imap + account, true, false, ""},
		{"rest only (implicit)", rest + tokenOnly, false, true, ""},
		{"both", imap + rest + both, true, true, ""},
		{"imap switched off", strings.Replace(imap, "[server]\n", "[server]\nenabled = false\n", 1) + rest + both, false, true, ""},
		{"rest switched off", imap + strings.Replace(rest, "[http]\n", "[http]\nenabled = false\n", 1) + both, true, false, ""},
		{"both switched off", strings.Replace(imap, "[server]\n", "[server]\nenabled = false\n", 1) +
			strings.Replace(rest, "[http]\n", "[http]\nenabled = false\n", 1) + both, false, false, "both endpoints are switched off"},
		{"nothing configured", account, false, false, "both endpoints are switched off"},
		{"enabled without listen", "[http]\nenabled = true\n" + imap + both, false, false, "requires http.listen"},
		{"switched-off section not validated", imap + "[http]\nenabled = false\nlisten = \":8080\"\n" + account, true, false, ""},
		{"token account but rest off", imap + tokenOnly, false, false, "account cannot be used"},
		{"password account but imap off", rest + account, false, false, "account cannot be used"},
	}
	for _, tt := range tests {
		cfg, err := loadCfg(t, tt.body)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%s: want error %q, got %v", tt.name, tt.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if cfg.Server.IMAPEnabled() != tt.imapOn || cfg.HTTP.IsEnabled() != tt.httpOn {
			t.Errorf("%s: imap=%v http=%v, want %v %v", tt.name, cfg.Server.IMAPEnabled(), cfg.HTTP.IsEnabled(), tt.imapOn, tt.httpOn)
		}
	}
}
