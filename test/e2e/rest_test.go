//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/restapi"
)

const apiToken = "irp_e2e-test-token-0123456789abcdefghijklmnop"

func startREST(t *testing.T, extra string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(apiToken))
	port, _ := strconv.Atoi(strings.Split(upstreamAddr, ":")[1])
	cfgText := fmt.Sprintf(`
[server]
enabled = false

[http]
listen = "127.0.0.1:0"
insecure_plaintext = true

[[accounts]]
local_user = "api"
api_token_sha256 = %q
remote_host = "127.0.0.1"
remote_port = %d
remote_security = "insecure-plaintext"
remote_user = %q
remote_password = %q
%s
`, hex.EncodeToString(sum[:]), port, upstreamUser, upstreamPass, extra)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.IMAPEnabled() || !cfg.HTTP.IsEnabled() {
		t.Fatal("endpoint switches not applied")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv := httptest.NewServer(restapi.New(cfg, log, nil).Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

func get(t *testing.T, method, u, token string) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func getJSON(t *testing.T, u string, want int) map[string]any {
	t.Helper()
	code, _, b := get(t, "GET", u, apiToken)
	if code != want {
		t.Fatalf("GET %s: status %d, want %d: %s", u, code, want, b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("GET %s: %v: %s", u, err, b)
	}
	return m
}

func TestRESTReadOnly(t *testing.T) {
	before := snapshot(t)
	base := startREST(t, `blocked_folders = ["Secret"]`)
	api := base + "/api/v1"

	// Authentication and methods.
	if code, _, _ := get(t, "GET", base+"/healthz", ""); code != 200 {
		t.Errorf("healthz: %d", code)
	}
	if code, h, _ := get(t, "GET", api+"/mailboxes", ""); code != 401 || h.Get("WWW-Authenticate") == "" {
		t.Errorf("no token: %d", code)
	}
	if code, _, _ := get(t, "GET", api+"/mailboxes", "wrong"); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if code, _, _ := get(t, m, api+"/mailboxes/INBOX/messages/1", apiToken); code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", m, code)
		}
	}

	// Mailboxes, folder filter.
	mbs := getJSON(t, api+"/mailboxes", 200)["mailboxes"].([]any)
	var names []string
	for _, m := range mbs {
		names = append(names, m.(map[string]any)["name"].(string))
	}
	got := strings.Join(names, ",")
	for _, want := range []string{"INBOX", "Drafts", "Reports"} {
		if !strings.Contains(got, want) {
			t.Errorf("mailbox %s missing: %s", want, got)
		}
	}
	if strings.Contains(got, "Secret") {
		t.Errorf("hidden mailbox listed: %s", got)
	}
	for _, p := range []string{"/mailboxes/Secret", "/mailboxes/secret/messages", "/mailboxes/Secret/messages/1", "/mailboxes/Secret/messages/1/raw"} {
		getJSON(t, api+p, 404)
	}
	if st := getJSON(t, api+"/mailboxes/INBOX", 200); st["messages"].(float64) != 3 || st["unseen"].(float64) != 3 {
		t.Errorf("status: %v", st)
	}

	// Message list: newest first, pagination, search.
	l := getJSON(t, api+"/mailboxes/INBOX/messages?limit=2", 200)
	msgs := l["messages"].([]any)
	if l["total"].(float64) != 3 || len(msgs) != 2 || msgs[0].(map[string]any)["subject"] != "Message 3 Grüße" {
		t.Fatalf("list: %v", l)
	}
	next := int(l["next_before_uid"].(float64))
	l2 := getJSON(t, api+"/mailboxes/INBOX/messages?limit=2&before_uid="+strconv.Itoa(next), 200)
	if m := l2["messages"].([]any); len(m) != 1 || m[0].(map[string]any)["subject"] != "Message 1" || l2["next_before_uid"] != nil {
		t.Errorf("page 2: %v", l2)
	}
	s := getJSON(t, api+"/mailboxes/INBOX/messages?subject="+url.QueryEscape("Grüße"), 200)
	if m := s["messages"].([]any); len(m) != 1 || m[0].(map[string]any)["message_id"] != "<m3@example.com>" {
		t.Errorf("utf-8 search: %v", s)
	}
	if s := getJSON(t, api+"/mailboxes/INBOX/messages?unseen=false", 200); s["total"].(float64) != 0 {
		t.Errorf("seen search: %v", s)
	}
	getJSON(t, api+"/mailboxes/INBOX/messages?bogus=1", 400)
	getJSON(t, api+"/mailboxes/INBOX/messages?subject=a%0D%0AX1%20DELETE%20INBOX", 400)
	getJSON(t, api+"/mailboxes/INBOX/messages/0", 400)
	getJSON(t, api+"/mailboxes/INBOX/messages/999", 404)
	getJSON(t, api+"/mailboxes/Nope/messages", 404)

	// Full message with MIME decoding and attachment.
	rl := getJSON(t, api+"/mailboxes/Reports/messages", 200)["messages"].([]any)
	if len(rl) != 1 {
		t.Fatalf("reports: %v", rl)
	}
	uid := strconv.Itoa(int(rl[0].(map[string]any)["uid"].(float64)))
	m := getJSON(t, api+"/mailboxes/Reports/messages/"+uid, 200)
	from := m["from"].([]any)[0].(map[string]any)
	if m["subject"] != "Monatsbericht für Oktober" || from["name"] != "Jürgen" ||
		!strings.Contains(m["text"].(string), "Grüße aus dem Bericht") || !strings.Contains(m["html"].(string), "<p>Report</p>") {
		t.Errorf("message: %v", m)
	}
	atts := m["attachments"].([]any)
	if len(atts) != 1 || atts[0].(map[string]any)["filename"] != "bericht.pdf" {
		t.Fatalf("attachments: %v", atts)
	}
	code, h, body := get(t, "GET", api+"/mailboxes/Reports/messages/"+uid+"/attachments/0", apiToken)
	if code != 200 || string(body) != "%PDF-1.4\n" || h.Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(h.Get("Content-Disposition"), "bericht.pdf") {
		t.Errorf("attachment: %d %q %v", code, body, h)
	}
	code, h, body = get(t, "GET", api+"/mailboxes/Reports/messages/"+uid+"/raw", apiToken)
	if code != 200 || !strings.HasPrefix(string(body), "From: ") || h.Get("Content-Type") != "message/rfc822" {
		t.Errorf("raw: %d %v", code, h)
	}
	getJSON(t, api+"/mailboxes/Reports/messages/"+uid+"/attachments/1", 404)
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("security headers missing: %v", h)
	}

	// Reading must not have changed anything, including \Seen.
	if after := snapshot(t); after != before {
		t.Errorf("upstream state changed by REST reads:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if st := getJSON(t, api+"/mailboxes/Reports", 200); st["unseen"].(float64) != 1 {
		t.Errorf("message marked as seen: %v", st)
	}
}

func TestRESTTokenLockout(t *testing.T) {
	base := startREST(t, "")
	for i := 0; i < 10; i++ {
		get(t, "GET", base+"/api/v1/mailboxes", "wrong")
	}
	if code, _, _ := get(t, "GET", base+"/api/v1/mailboxes", apiToken); code != http.StatusTooManyRequests {
		t.Errorf("after 10 failures: %d, want 429", code)
	}
}
