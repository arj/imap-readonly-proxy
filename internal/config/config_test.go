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
