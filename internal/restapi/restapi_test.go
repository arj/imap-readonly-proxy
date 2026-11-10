package restapi

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/imapwire"
	"github.com/arj/imap-readonly-proxy/internal/policy"
)

func upstreamText(t *testing.T, req *policy.Request) string {
	t.Helper()
	var b bytes.Buffer
	for _, p := range req.Upstream {
		if p.IsLiteral {
			b.WriteString("{LIT}")
			b.Write(p.Literal)
			continue
		}
		b.Write(p.Text)
	}
	return b.String()
}

func TestGeneratedCommandsPassPolicy(t *testing.T) {
	g := &gateway{acct: &config.Account{BlockedFolders: []string{"Secret"}}, state: policy.Selected,
		caps: policy.UpstreamCaps{Unselect: true}}
	cases := []struct {
		query string
		want  string
	}{
		{"", "UID SEARCH (ALL)\r\n"},
		{"?subject=Gr%C3%BC%C3%9Fe&unseen=true", "UID SEARCH CHARSET UTF-8 (SUBJECT {LIT}Grüße UNSEEN)\r\n"},
		{"?from=a%22b%5Cc&since=2026-01-02&flagged=false", "UID SEARCH (FROM \"a\\\"b\\\\c\" SINCE 2-Jan-2026 UNFLAGGED)\r\n"},
		{"?text=x&before=2026-12-31&on=2026-11-09", "UID SEARCH (TEXT \"x\" BEFORE 31-Dec-2026 ON 9-Nov-2026)\r\n"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/v1/mailboxes/INBOX/messages"+c.query, nil)
		keys, u8, err := searchKeys(r)
		if err != nil {
			t.Fatalf("%s: %v", c.query, err)
		}
		req, err := g.prepare(searchCommand(keys, u8, 0))
		if err != nil {
			t.Fatalf("%s: rejected: %v", c.query, err)
		}
		if got := upstreamText(t, req); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.query, got, c.want)
		}
	}
	r := httptest.NewRequest("GET", "/x?subject=a", nil)
	keys, _, _ := searchKeys(r)
	req, err := g.prepare(searchCommand(keys, false, 42))
	if err != nil || upstreamText(t, req) != "UID SEARCH UID 1:41 (SUBJECT \"a\")\r\n" {
		t.Errorf("before_uid: %v %q", err, upstreamText(t, req))
	}
	req, err = g.prepare(summaryFetchCommand([]uint32{3, 2, 1}))
	if err != nil || !strings.Contains(upstreamText(t, req), "BODY.PEEK[HEADER.FIELDS (From To Cc Reply-To Subject Date Message-ID In-Reply-To)]") {
		t.Errorf("summary fetch: %v %q", err, upstreamText(t, req))
	}
	req, err = g.prepare(new(imapwire.Builder).Atom("UID FETCH 7 (UID BODY.PEEK[])"))
	if err != nil || upstreamText(t, req) != "UID FETCH 7 (UID BODY.PEEK[])\r\n" {
		t.Errorf("body fetch: %v %q", err, upstreamText(t, req))
	}
	// Hidden folders are refused before anything is sent.
	g.state = policy.Authenticated
	if _, err := g.prepare(new(imapwire.Builder).Atom("EXAMINE").SP().String([]byte("secret"))); err != errNotFound {
		t.Errorf("hidden folder: %v", err)
	}
	// Writes are impossible even if the REST code had a bug.
	for _, cmd := range []string{"STORE 1 +FLAGS (\\Seen)", "DELETE INBOX", "SELECT INBOX x", "FETCH 1 RFC822"} {
		g.state = policy.Selected
		if _, err := g.prepare(new(imapwire.Builder).Atom(cmd)); err == nil {
			t.Errorf("%q accepted", cmd)
		}
	}
	g.state = policy.Authenticated
	req, err = g.prepare(new(imapwire.Builder).Atom("SELECT INBOX"))
	if err != nil || upstreamText(t, req) != "EXAMINE \"INBOX\"\r\n" {
		t.Errorf("SELECT not rewritten: %v", err)
	}
}

func TestSearchKeysRejectsBadInput(t *testing.T) {
	for _, q := range []string{"?foo=1", "?subject=", "?subject=a%0D%0Ab", "?since=1.1.2026", "?unseen=maybe",
		"?subject=a&subject=b", "?subject=%FF"} {
		r := httptest.NewRequest("GET", "/x"+q, nil)
		if _, _, err := searchKeys(r); err == nil {
			t.Errorf("%s accepted", q)
		}
	}
}

func TestMailboxUTF7(t *testing.T) {
	for utf, enc := range map[string]string{
		"INBOX": "INBOX", "Entwürfe": "Entw&APw-rfe", "A&B": "A&-B", "日本語": "&ZeVnLIqe-", "Sent/Ärger": "Sent/&AMQ-rger",
	} {
		if got := encodeMailbox(utf); got != enc {
			t.Errorf("encode %q = %q, want %q", utf, got, enc)
		}
		if got, err := decodeMailbox(enc); err != nil || got != utf {
			t.Errorf("decode %q = %q %v", enc, got, err)
		}
	}
	for _, bad := range []string{"&", "&AGE-", "&APw", "a\x01", "&AGEAYg-"} {
		if _, err := decodeMailbox(bad); err == nil {
			t.Errorf("decode %q accepted", bad)
		}
	}
}

func FuzzMailboxUTF7(f *testing.F) {
	f.Add("Entw&APw-rfe")
	f.Add("&ZeVnLIqe-/x")
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := decodeMailbox(s); err == nil && encodeMailbox(d) != s {
			t.Fatalf("roundtrip %q -> %q -> %q", s, d, encodeMailbox(d))
		}
	})
}

func TestParseResponse(t *testing.T) {
	data := []byte("* 12 FETCH (UID 7 FLAGS (\\Seen $Junk) INTERNALDATE \" 9-Nov-2026 10:00:00 +0100\" RFC822.SIZE 345 BODY[HEADER.FIELDS (FROM SUBJECT)] {28}\r\nSubject: hi\r\nFrom: a@b.c\r\n\r\n)\r\n")
	it, ok := parseFetch(data)
	if !ok || it.uid != 7 || it.size != 345 || len(it.flags) != 2 || it.internalDate != "2026-11-09T10:00:00+01:00" {
		t.Fatalf("parseFetch: %+v %v", it, ok)
	}
	env := envelopeFrom(parseHeaderBlock(it.header))
	if env.Subject != "hi" || len(env.From) != 1 || env.From[0].Address != "a@b.c" {
		t.Errorf("envelope: %+v", env)
	}
	v, err := parseResponse([]byte("* LIST (\\HasNoChildren) \"/\" {5}\r\nA B C\r\n"))
	if err != nil || len(v) != 4 || v[3].str() != "A B C" {
		t.Errorf("list: %v %v", v, err)
	}
	for _, bad := range []string{"* (", "* \"x", "* {9}\r\nab\r\n", "* A  B\r\n", "x\r\n"} {
		if _, err := parseResponse([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte("* 1 FETCH (UID 1 BODY[] {3}\r\nabc)\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseResponse(b)
		_, _ = parseFetch(b)
	})
}

const multipartMsg = "From: =?UTF-8?Q?J=C3=BCrgen?= <j@example.org>\r\n" +
	"To: a@example.org, \"B, C\" <b@example.org>\r\n" +
	"Subject: =?ISO-8859-1?Q?Gr=FC=DFe?=\r\n" +
	"Date: Mon, 9 Nov 2026 10:00:00 +0100\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
	"--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n" +
	"--inner\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nGr=FC=DFe\r\n" +
	"--inner\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Gr\xc3\xbc\xc3\x9fe</p>\r\n--inner--\r\n" +
	"--outer\r\nContent-Type: application/pdf; name=\"r.pdf\"\r\nContent-Disposition: attachment; filename=\"r.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBE\r\nRi0x\r\n--outer--\r\n"

func TestParseMessage(t *testing.T) {
	p, err := parseMessage([]byte(multipartMsg))
	if err != nil {
		t.Fatal(err)
	}
	if p.Envelope.Subject != "Grüße" || p.Envelope.From[0].Name != "Jürgen" || len(p.Envelope.To) != 2 {
		t.Errorf("envelope: %+v", p.Envelope)
	}
	if strings.TrimSpace(p.Text) != "Grüße" || !strings.Contains(p.HTML, "Grüße") {
		t.Errorf("bodies: %q %q", p.Text, p.HTML)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Filename != "r.pdf" || string(p.data[0]) != "%PDF-1" {
		t.Errorf("attachments: %+v %q", p.Attachments, p.data)
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte(multipartMsg))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseMessage(b)
	})
}
