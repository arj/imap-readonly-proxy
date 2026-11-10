//go:build e2e

// Package e2e runs the proxy against a real IMAP server (Dovecot) and checks
// that no write reaches the server. See run.sh.
//
// Environment:
//
//	IRP_UPSTREAM_PORT  port of a plaintext IMAP server on 127.0.0.1
//	IRP_UPSTREAM_USER  upstream user name
//	IRP_UPSTREAM_PASS  upstream password
package e2e

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/proxy"
)

const localUser, localPass = "reader", "reader-pw"

var upstreamAddr, upstreamUser, upstreamPass string

func TestMain(m *testing.M) {
	port := os.Getenv("IRP_UPSTREAM_PORT")
	if port == "" {
		fmt.Println("IRP_UPSTREAM_PORT not set; skipping e2e tests")
		os.Exit(0)
	}
	upstreamAddr = "127.0.0.1:" + port
	upstreamUser = os.Getenv("IRP_UPSTREAM_USER")
	upstreamPass = os.Getenv("IRP_UPSTREAM_PASS")
	os.Exit(m.Run())
}

func startProxy(t *testing.T, extra string) string {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(localPass), bcrypt.MinCost)
	dir := t.TempDir()
	port, _ := strconv.Atoi(strings.Split(upstreamAddr, ":")[1])
	cfgText := fmt.Sprintf(`
[server]
listen = "127.0.0.1:0"
insecure_plaintext = true

[[accounts]]
local_user = %q
local_password_hash = %q
remote_host = "127.0.0.1"
remote_port = %d
remote_security = "insecure-plaintext"
remote_user = %q
remote_password = %q
%s
`, localUser, string(hash), port, upstreamUser, upstreamPass, extra)
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv := proxy.New(cfg, log, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

type client struct {
	t  *testing.T
	nc net.Conn
	r  *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, nc: nc, r: bufio.NewReader(nc)}
	t.Cleanup(func() { nc.Close() })
	if _, err := c.line(); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	return c
}

func (c *client) line() (string, error) {
	_ = c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	l, err := c.r.ReadString('\n')
	return l, err
}

// cmd sends raw bytes and returns all output until the tagged response for
// tag (or EOF/timeout).
func (c *client) cmd(tag, raw string) string {
	c.t.Helper()
	if _, err := io.WriteString(c.nc, raw); err != nil {
		return "WRITE-ERROR " + err.Error()
	}
	var out strings.Builder
	for {
		l, err := c.line()
		out.WriteString(l)
		if err != nil {
			return out.String()
		}
		if tag != "" && strings.HasPrefix(l, tag+" ") {
			return out.String()
		}
		if m := regexp.MustCompile(`\{(\d+)\}\r\n$`).FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			buf := make([]byte, n)
			io.ReadFull(c.r, buf)
			out.Write(buf)
		}
	}
}

// drain reads output for a short time.
func (c *client) drain(d time.Duration) string {
	var out strings.Builder
	_ = c.nc.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	for {
		n, err := c.r.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			return out.String()
		}
	}
}

func login(t *testing.T, addr string) *client {
	c := dial(t, addr)
	out := c.cmd("L1", fmt.Sprintf("L1 LOGIN %s %s\r\n", localUser, localPass))
	if !strings.Contains(out, "L1 OK") {
		t.Fatalf("login failed: %q", out)
	}
	return c
}

// snapshot returns a description of the full upstream state, read directly
// from the upstream server.
func snapshot(t *testing.T) string {
	t.Helper()
	nc, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	c := &client{t: t, nc: nc, r: bufio.NewReader(nc)}
	c.line()
	c.cmd("s1", fmt.Sprintf("s1 LOGIN %s %s\r\n", upstreamUser, upstreamPass))
	list := c.cmd("s2", "s2 LIST \"\" \"*\"\r\n")
	lsub := c.cmd("s3", "s3 LSUB \"\" \"*\"\r\n")
	var boxes []string
	for _, l := range strings.Split(list, "\r\n") {
		if strings.HasPrefix(l, "* LIST ") {
			f := strings.Fields(l)
			boxes = append(boxes, strings.Trim(f[len(f)-1], "\""))
		}
	}
	sort.Strings(boxes)
	var sb strings.Builder
	sb.WriteString("MAILBOXES " + strings.Join(boxes, ",") + "\n")
	sb.WriteString("LSUB " + normalize(lsub) + "\n")
	for _, b := range boxes {
		ex := c.cmd("s4", fmt.Sprintf("s4 EXAMINE %q\r\n", b))
		fe := c.cmd("s5", "s5 UID FETCH 1:* (FLAGS RFC822.SIZE)\r\n")
		sb.WriteString(b + " " + grepLines(ex, "EXISTS", "UIDVALIDITY", "UIDNEXT") + " " + normalize(fe) + "\n")
	}
	return sb.String()
}

var timing = regexp.MustCompile(` \([0-9.+ ]+secs\)`)

// recent matches \Recent, which the server changes on its own whenever a
// session SELECTs the mailbox; clients cannot set or clear it.
var recent = regexp.MustCompile(` ?\\Recent`)

func normalize(s string) string {
	s = timing.ReplaceAllString(s, "")
	s = recent.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "FLAGS ( ", "FLAGS (")
	return strings.ReplaceAll(s, "\r\n", " | ")
}

func grepLines(s string, keys ...string) string {
	var out []string
	for _, l := range strings.Split(s, "\r\n") {
		for _, k := range keys {
			if strings.Contains(l, k) {
				out = append(out, l)
			}
		}
	}
	return strings.Join(out, ";")
}

// attacks are raw byte sequences sent after login (and EXAMINE INBOX for
// those marked selected). None of them may change upstream state.
var attacks = []struct {
	name     string
	selected bool
	raw      string
	mayOK    bool // read-only commands that are allowed to succeed
}{
	{"STORE", true, "a1 STORE 1 +FLAGS (\\Deleted \\Seen)\r\n", false},
	{"UID STORE", true, "a1 UID STORE 1:* +FLAGS (\\Deleted \\Seen)\r\n", false},
	{"SELECT then STORE", false, "a0 SELECT INBOX\r\na1 STORE 1 +FLAGS (\\Seen)\r\n", false},
	{"COPY", true, "a1 COPY 1 Drafts\r\n", false},
	{"MOVE", true, "a1 MOVE 1 Drafts\r\n", false},
	{"UID MOVE", true, "a1 UID MOVE 1:* Drafts\r\n", false},
	{"EXPUNGE", true, "a1 EXPUNGE\r\n", false},
	{"UID EXPUNGE", true, "a1 UID EXPUNGE 1:*\r\n", false},
	{"APPEND sync", false, "a1 APPEND INBOX {5}\r\nhello\r\n", false},
	{"APPEND LITERAL+", false, "a1 APPEND INBOX {5+}\r\nhello\r\n", false},
	{"CREATE", false, "a1 CREATE NewBox\r\n", false},
	{"DELETE", false, "a1 DELETE Drafts\r\n", false},
	{"RENAME", false, "a1 RENAME Drafts Renamed\r\n", false},
	{"SUBSCRIBE", false, "a1 SUBSCRIBE Secret\r\n", false},
	{"UNSUBSCRIBE", false, "a1 UNSUBSCRIBE INBOX\r\n", false},
	{"SETACL", false, "a1 SETACL INBOX anyone lrswipkxtea\r\n", false},
	{"SETMETADATA", false, "a1 SETMETADATA INBOX (/private/comment \"x\")\r\n", false},
	{"REPLACE", true, "a1 REPLACE 1 INBOX {5+}\r\nhello\r\n", false},
	{"UID REPLACE", true, "a1 UID REPLACE 1 INBOX {5+}\r\nhello\r\n", false},
	{"COMPRESS then DELETE", false, "a1 COMPRESS DEFLATE\r\na2 DELETE Drafts\r\n", false},
	{"ENABLE", false, "a1 ENABLE QRESYNC UTF8=ACCEPT\r\n", false},
	{"UNAUTHENTICATE", false, "a1 UNAUTHENTICATE\r\n", false},
	{"CLOSE after flag", true, "a1 STORE 1 +FLAGS (\\Deleted)\r\na2 CLOSE\r\n", true},
	{"bogus literal {+N}", false, "a1 NOOP {+18}\r\nb1 DELETE Drafts\r\n", false},
	{"literal with leading zeros", false, "a1 NOOP {018}\r\nb1 DELETE Drafts\r\n", false},
	{"sync literal on unknown command", false, "a1 XFOO {18}\r\nb1 DELETE Drafts\r\n", false},
	{"sync literal on NOOP", false, "a1 NOOP {18}\r\nb1 DELETE Drafts\r\n", false},
	{"literal inside SEARCH", true, "a1 SEARCH SUBJECT {18}\r\nb1 DELETE Drafts\r\n\r\n", false},
	{"IDLE smuggle", false, "a1 IDLE\r\nb1 DELETE Drafts\r\nDONE\r\n", false},
	{"IDLE smuggle after garbage", false, "a1 IDLE\r\nXX\r\nb1 DELETE Drafts\r\nDONE\r\n", false},
	{"tab separated", false, "a1\tDELETE\tDrafts\r\n", false},
	{"leading space", false, " DELETE Drafts\r\n", false},
	{"bare LF", false, "a1 DELETE Drafts\nb1 NOOP\r\n", false},
	{"embedded CR", false, "a1 NOOP\rb1 DELETE Drafts\r\n", false},
	{"NUL byte", false, "a1 NOOP\x00b1 DELETE Drafts\r\n", false},
	{"quoted CRLF", true, "a1 SEARCH SUBJECT \"x\r\nb1 DELETE Drafts\"\r\n", false},
	{"quoted escape", true, "a1 SEARCH SUBJECT \"x\\\" DELETE Drafts\"\r\n", true},
	{"RFC822 sets seen", true, "a1 FETCH 1:* RFC822\r\n", false},
	{"RFC822.TEXT sets seen", true, "a1 FETCH 1:* RFC822.TEXT\r\n", false},
	{"BODY[] sets seen", true, "a1 FETCH 1:* BODY[]\r\n", true},
	{"UID BODY[TEXT]", true, "a1 UID FETCH 1:* (BODY[TEXT] BODY[1] BODY[HEADER.FIELDS (SUBJECT)])\r\n", true},
	{"BINARY", true, "a1 FETCH 1:* BINARY[]\r\n", false},
	{"FETCH modifier", true, "a1 FETCH 1:* (FLAGS) (CHANGEDSINCE 1)\r\n", false},
	{"SELECT with QRESYNC", false, "a1 SELECT INBOX (CONDSTORE)\r\n", false},
	{"post-auth LOGIN", false, "a1 LOGIN alice alicepw\r\n", false},
	{"NOTIFY", false, "a1 NOTIFY SET (selected MessageNew)\r\n", false},
	{"X-command", false, "a1 XAPPLEPUSHSERVICE aps-version 2\r\n", false},
	{"huge literal", false, "a1 SEARCH SUBJECT {999999999}\r\n", false},
	{"long line", false, "a1 NOOP " + strings.Repeat("A", 20000) + "\r\nb1 DELETE Drafts\r\n", false},
}

func TestNoWritesReachUpstream(t *testing.T) {
	addr := startProxy(t, "")
	before := snapshot(t)
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			c := login(t, addr)
			if a.selected {
				if out := c.cmd("e1", "e1 EXAMINE INBOX\r\n"); !strings.Contains(out, "e1 OK") {
					t.Fatalf("EXAMINE failed: %q", out)
				}
			}
			io.WriteString(c.nc, a.raw)
			out := c.drain(700 * time.Millisecond)
			t.Logf("response: %q", out)
			if !a.mayOK {
				for _, bad := range []string{"a1 OK", "a2 OK", "b1 OK"} {
					if strings.Contains(out, bad) {
						t.Errorf("unexpected success %q in %q", bad, out)
					}
				}
			}
			if strings.Contains(out, "b1 OK") {
				t.Errorf("smuggled command executed: %q", out)
			}
			c.cmd("z", "z LOGOUT\r\n")
		})
	}
	after := snapshot(t)
	if before != after {
		t.Fatalf("upstream state changed\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestReadFunctions(t *testing.T) {
	addr := startProxy(t, "")
	before := snapshot(t)
	c := login(t, addr)

	if out := c.cmd("c1", "c1 CAPABILITY\r\n"); strings.Contains(out, "COMPRESS") || strings.Contains(out, "MOVE") || !strings.Contains(out, "IDLE") {
		t.Errorf("capabilities not filtered: %q", out)
	}
	if out := c.cmd("l1", "l1 LIST \"\" \"*\"\r\n"); !strings.Contains(out, "INBOX") || !strings.Contains(out, "l1 OK") {
		t.Errorf("LIST: %q", out)
	}
	if out := c.cmd("s1", "s1 STATUS INBOX (MESSAGES UNSEEN UIDNEXT)\r\n"); !strings.Contains(out, "MESSAGES 3") {
		t.Errorf("STATUS: %q", out)
	}
	out := c.cmd("x1", "x1 SELECT INBOX\r\n")
	if !strings.Contains(out, "[READ-ONLY]") || !strings.Contains(out, "3 EXISTS") {
		t.Errorf("SELECT was not turned into EXAMINE: %q", out)
	}
	out = c.cmd("f1", "f1 FETCH 1 (UID FLAGS ENVELOPE BODY[])\r\n")
	if !strings.Contains(out, "Subject: Message 1") || !strings.Contains(out, "f1 OK") {
		t.Errorf("FETCH: %q", out)
	}
	out = c.cmd("f2", "f2 UID FETCH 1:* (BODY.PEEK[HEADER.FIELDS (SUBJECT)] RFC822.SIZE)\r\n")
	if strings.Count(out, "Subject: Message") != 3 {
		t.Errorf("UID FETCH: %q", out)
	}
	if out := c.cmd("q1", "q1 SEARCH CHARSET UTF-8 OR SUBJECT \"Message 2\" SUBJECT {7+}\r\nGrüße\r\n"); !strings.Contains(out, "* SEARCH 2 3") {
		t.Errorf("SEARCH: %q", out)
	}
	if out := c.cmd("q2", "q2 UID SEARCH UNSEEN SINCE 1-Jan-2000 NOT DELETED\r\n"); !strings.Contains(out, "q2 OK") {
		t.Errorf("UID SEARCH: %q", out)
	}
	if out := c.cmd("u1", "u1 UNSELECT\r\n"); !strings.Contains(out, "u1 OK") {
		t.Errorf("UNSELECT: %q", out)
	}
	if after := snapshot(t); after != before {
		t.Fatalf("reading changed upstream state (\\Seen?)\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestIdleRelaysUpdates(t *testing.T) {
	addr := startProxy(t, "")
	c := login(t, addr)
	c.cmd("e1", "e1 EXAMINE Drafts\r\n")
	io.WriteString(c.nc, "i1 IDLE\r\n")
	if l, _ := c.line(); !strings.HasPrefix(l, "+") {
		t.Fatalf("no IDLE continuation: %q", l)
	}
	// Append directly upstream, then remove it again so state is restored.
	nc, _ := net.Dial("tcp", upstreamAddr)
	u := &client{t: t, nc: nc, r: bufio.NewReader(nc)}
	u.line()
	u.cmd("u1", fmt.Sprintf("u1 LOGIN %s %s\r\n", upstreamUser, upstreamPass))
	u.cmd("u2", "u2 APPEND Drafts {8+}\r\nSubj: x\n\r\n")
	got := c.drain(3 * time.Second)
	if !strings.Contains(got, "EXISTS") {
		t.Errorf("no EXISTS during IDLE: %q", got)
	}
	if out := c.cmd("i1", "DONE\r\n"); !strings.Contains(out, "i1 OK") {
		t.Errorf("IDLE completion: %q", out)
	}
	u.cmd("u3", "u3 SELECT Drafts\r\n")
	u.cmd("u4", "u4 STORE 1:* +FLAGS (\\Deleted)\r\n")
	u.cmd("u5", "u5 EXPUNGE\r\n")
	nc.Close()
}

func TestFolderFilter(t *testing.T) {
	addr := startProxy(t, `allowed_folders = ["INBOX", "Drafts"]`)
	c := login(t, addr)
	if out := c.cmd("l1", "l1 LIST \"\" \"*\"\r\n"); strings.Contains(out, "Secret") || !strings.Contains(out, "Drafts") {
		t.Errorf("LIST not filtered: %q", out)
	}
	for _, raw := range []string{
		"t1 EXAMINE Secret\r\n",
		"t1 SELECT \"Secret\"\r\n",
		"t1 EXAMINE {6}\r\nSecret\r\n",
		"t1 EXAMINE secret\r\n",
		"t1 STATUS Secret (MESSAGES)\r\n",
		"t1 STATUS {6+}\r\nSecret (MESSAGES)\r\n",
	} {
		io.WriteString(c.nc, raw)
		out := c.drain(800 * time.Millisecond)
		if !strings.Contains(out, "t1 NO") {
			t.Errorf("%q: hidden folder reachable: %q", raw, out)
		}
	}

	addr2 := startProxy(t, `blocked_folders = ["Secret"]`)
	c2 := login(t, addr2)
	if out := c2.cmd("l1", "l1 LIST \"\" \"*\"\r\n"); strings.Contains(out, "Secret") {
		t.Errorf("LIST not filtered: %q", out)
	}
	if out := c2.cmd("t2", "t2 EXAMINE SECRET\r\n"); !strings.Contains(out, "t2 NO") {
		t.Errorf("case variant of blocked folder reachable: %q", out)
	}
}

func TestLoginThrottling(t *testing.T) {
	addr := startProxy(t, "")
	c := dial(t, addr)
	for i := 0; i < 3; i++ {
		out := c.cmd("l", "l LOGIN reader wrong\r\n")
		if !strings.Contains(out, "l NO") {
			t.Fatalf("wrong password accepted: %q", out)
		}
	}
	if _, err := io.WriteString(c.nc, "x NOOP\r\n"); err == nil {
		if out := c.drain(500 * time.Millisecond); strings.Contains(out, "x OK") {
			t.Errorf("connection kept open after 3 failures")
		}
	}
}

// TestSnapshotDetectsChanges guards against a snapshot that is blind to
// the changes the other tests look for.
func TestSnapshotDetectsChanges(t *testing.T) {
	before := snapshot(t)
	nc, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	u := &client{t: t, nc: nc, r: bufio.NewReader(nc)}
	u.line()
	u.cmd("u1", fmt.Sprintf("u1 LOGIN %s %s\r\n", upstreamUser, upstreamPass))
	u.cmd("u2", "u2 SELECT INBOX\r\n")
	u.cmd("u3", "u3 STORE 1 +FLAGS (\\Seen)\r\n")
	changed := snapshot(t)
	u.cmd("u4", "u4 STORE 1 -FLAGS (\\Seen)\r\n")
	if changed == before {
		t.Fatal("snapshot did not detect a \\Seen change")
	}
	if snapshot(t) != before {
		t.Fatal("could not restore state")
	}
}
