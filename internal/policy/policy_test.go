package policy

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/arj/imap-readonly-proxy/internal/imapwire"
)

var allCaps = UpstreamCaps{Idle: true, Unselect: true, Namespace: true}

func parseRaw(t testing.TB, raw string, st State) (*Request, *Reject, error) {
	rc, err := imapwire.ReadCommand(bufio.NewReader(strings.NewReader(raw)), imapwire.DefaultLimits, nil)
	if err != nil {
		return nil, nil, err
	}
	toks, err := imapwire.Tokenize(rc)
	if err != nil {
		return nil, nil, err
	}
	req, rej := Parse(toks, st, allCaps)
	return req, rej, nil
}

// wire renders upstream parts the way the upstream sender does with
// LITERAL+.
func wire(parts []imapwire.Part) string {
	var b bytes.Buffer
	for _, p := range parts {
		if p.IsLiteral {
			b.WriteString("{")
			b.WriteString(itoa(len(p.Literal)))
			b.WriteString("+}\r\n")
			b.Write(p.Literal)
			continue
		}
		b.Write(p.Text)
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestAllowedCommands(t *testing.T) {
	tests := []struct {
		raw  string
		st   State
		want string // upstream command, "" for local
	}{
		{"a CAPABILITY\r\n", NotAuthenticated, ""},
		{"a LOGIN user pass\r\n", NotAuthenticated, ""},
		{"a LOGIN {4+}\r\nuser {4+}\r\npass\r\n", NotAuthenticated, ""},
		{"a SELECT INBOX\r\n", Authenticated, "EXAMINE \"INBOX\"\r\n"},
		{"a select \"Sent Items\"\r\n", Authenticated, "EXAMINE \"Sent Items\"\r\n"},
		{"a EXAMINE {6+}\r\nDrafts\r\n", Authenticated, "EXAMINE \"Drafts\"\r\n"},
		{"a STATUS INBOX (MESSAGES unseen)\r\n", Authenticated, "STATUS \"INBOX\" (MESSAGES UNSEEN)\r\n"},
		{"a LIST \"\" *\r\n", Authenticated, "LIST \"\" \"*\"\r\n"},
		{"a LSUB \"\" %\r\n", Authenticated, "LSUB \"\" \"%\"\r\n"},
		{"a NOOP\r\n", Authenticated, "NOOP\r\n"},
		{"a IDLE\r\n", Authenticated, "IDLE\r\n"},
		{"a NAMESPACE\r\n", Authenticated, "NAMESPACE\r\n"},
		{"a CLOSE\r\n", Selected, "UNSELECT\r\n"},
		{"a FETCH 1:* FAST\r\n", Selected, "FETCH 1:* FAST\r\n"},
		{"a FETCH 1 BODY[]\r\n", Selected, "FETCH 1 BODY.PEEK[]\r\n"},
		{"a fetch 1,3:5 (uid flags body[1.2.mime] body[text]<0.100>)\r\n", Selected,
			"FETCH 1,3:5 (UID FLAGS BODY.PEEK[1.2.MIME] BODY.PEEK[TEXT]<0.100>)\r\n"},
		{"a UID FETCH 1:* (BODY.PEEK[HEADER.FIELDS (From \"X-Foo\")] RFC822.SIZE)\r\n", Selected,
			"UID FETCH 1:* (BODY.PEEK[HEADER.FIELDS (From X-Foo)] RFC822.SIZE)\r\n"},
		{"a FETCH 2 BODY[HEADER.FIELDS.NOT (Received)]<0.1024>\r\n", Selected,
			"FETCH 2 BODY.PEEK[HEADER.FIELDS.NOT (Received)]<0.1024>\r\n"},
		{"a SEARCH UNSEEN\r\n", Selected, "SEARCH UNSEEN\r\n"},
		{"a UID SEARCH CHARSET utf-8 OR FROM alice (SINCE 1-Jan-2020 NOT DELETED) 1:10\r\n", Selected,
			"UID SEARCH CHARSET UTF-8 OR FROM \"alice\" (SINCE 1-Jan-2020 NOT DELETED) 1:10\r\n"},
		{"a SEARCH SUBJECT {6+}\r\nGrüß\r\n", Selected, "SEARCH SUBJECT {6+}\r\nGrüß\r\n"},
		{"a SEARCH HEADER X-Spam yes LARGER 100 UID 5:*\r\n", Selected,
			"SEARCH HEADER \"X-Spam\" \"yes\" LARGER 100 UID 5:*\r\n"},
	}
	for _, tt := range tests {
		req, rej, err := parseRaw(t, tt.raw, tt.st)
		if err != nil || rej != nil {
			t.Errorf("%q: unexpected rejection %v %+v", tt.raw, err, rej)
			continue
		}
		got := ""
		if tt.want != "" || req.Action != ActLogin && req.Action != ActCapability {
			got = wire(req.Upstream)
		}
		if got != tt.want {
			t.Errorf("%q:\n got %q\nwant %q", tt.raw, got, tt.want)
		}
	}
}

func TestRejectedCommands(t *testing.T) {
	sel := []string{
		"a STORE 1 +FLAGS (\\Seen)\r\n",
		"a UID STORE 1 +FLAGS (\\Seen)\r\n",
		"a COPY 1 Trash\r\n", "a UID COPY 1 Trash\r\n",
		"a MOVE 1 Trash\r\n", "a UID MOVE 1 Trash\r\n",
		"a EXPUNGE\r\n", "a UID EXPUNGE 1\r\n",
		"a APPEND INBOX {1+}\r\nx\r\n",
		"a CREATE x\r\n", "a DELETE x\r\n", "a RENAME x y\r\n",
		"a SUBSCRIBE x\r\n", "a UNSUBSCRIBE x\r\n",
		"a SETACL INBOX bob lr\r\n", "a DELETEACL INBOX bob\r\n",
		"a SETMETADATA INBOX (/private/x \"y\")\r\n", "a SETQUOTA \"\" (STORAGE 1)\r\n",
		"a REPLACE 1 INBOX {1+}\r\nx\r\n", "a UID REPLACE 1 INBOX {1+}\r\nx\r\n",
		"a COMPRESS DEFLATE\r\n", "a ENABLE QRESYNC\r\n", "a UNAUTHENTICATE\r\n",
		"a STARTTLS\r\n", "a AUTHENTICATE PLAIN\r\n", "a LOGIN a b\r\n",
		"a CHECK\r\n", "a ID NIL\r\n", "a NOTIFY NONE\r\n", "a XLIST \"\" *\r\n",
		"a GETMETADATA INBOX /private/x\r\n", "a SORT (DATE) UTF-8 ALL\r\n",
		"a THREAD REFS UTF-8 ALL\r\n", "a UID THREAD REFS UTF-8 ALL\r\n",
		"a SELECT INBOX (CONDSTORE)\r\n", "a EXAMINE INBOX (QRESYNC (1 1))\r\n",
		"a LIST (SUBSCRIBED) \"\" *\r\n", "a LIST \"\" * RETURN (STATUS (MESSAGES))\r\n",
		"a FETCH 1 RFC822\r\n", "a FETCH 1 RFC822.TEXT\r\n", "a FETCH 1 BINARY[]\r\n",
		"a FETCH 1 BINARY.PEEK[1]\r\n", "a FETCH 1 (FLAGS) (CHANGEDSINCE 1)\r\n",
		"a FETCH 1 MODSEQ\r\n", "a FETCH 1 X-GM-LABELS\r\n", "a FETCH 1 BODY[HEADER.FIELDS]\r\n",
		"a FETCH 1 BODY[0]\r\n", "a FETCH 1 BODY[MIME]\r\n", "a FETCH 1 BODY[]<0.0>\r\n",
		"a FETCH 0 FLAGS\r\n", "a FETCH $ FLAGS\r\n", "a FETCH 1:x FLAGS\r\n",
		"a FETCH 1 BODY[1.TEXT.X]\r\n", "a FETCH 1 (FLAGS\r\n", "a FETCH 1 ALL FAST\r\n",
		"a SEARCH RETURN (ALL) ALL\r\n", "a SEARCH CHARSET ISO-8859-1 ALL\r\n",
		"a SEARCH MODSEQ 1\r\n", "a SEARCH X-GM-RAW foo\r\n", "a SEARCH $\r\n",
		"a SEARCH SINCE 2020-01-01\r\n", "a SEARCH KEYWORD \\Seen\r\n",
		"a SEARCH SUBJECT {2+}\r\n\r\n\r\n", "a SEARCH\r\n",
		"a SEARCH " + strings.Repeat("NOT ", 40) + "ALL\r\n",
		"a STATUS INBOX (SIZE)\r\n", "a STATUS INBOX (HIGHESTMODSEQ)\r\n", "a STATUS INBOX ()\r\n",
		"a SELECT {4+}\r\nIN\x01X\r\n", "a SELECT \"\"\r\n", "a SELECT a b\r\n",
		"a IDLE now\r\n", "a NOOP x\r\n", "a UID\r\n", "a UID FOO\r\n",
		"+ STORE 1 +FLAGS (\\Seen)\r\n", "* STORE 1 FLAGS ()\r\n", "a{ NOOP\r\n",
	}
	for _, raw := range sel {
		req, rej, err := parseRaw(t, raw, Selected)
		if err == nil && rej == nil {
			t.Errorf("%q accepted as %q", raw, wire(req.Upstream))
		}
	}
	for _, raw := range []string{"a SELECT INBOX\r\n", "a FETCH 1 FLAGS\r\n", "a LIST \"\" *\r\n"} {
		if _, rej, err := parseRaw(t, raw, NotAuthenticated); err == nil && rej == nil {
			t.Errorf("%q accepted before login", raw)
		}
	}
	for _, raw := range []string{"a FETCH 1 FLAGS\r\n", "a SEARCH ALL\r\n", "a CLOSE\r\n"} {
		if _, rej, err := parseRaw(t, raw, Authenticated); err == nil && rej == nil {
			t.Errorf("%q accepted without selected mailbox", raw)
		}
	}
}

func TestFramingIsStrict(t *testing.T) {
	for _, raw := range []string{
		"a NOOP {+5}\r\nhello\r\n",
		"a NOOP {5 }\r\nhello\r\n",
		"a NOOP {-1}\r\n",
		"a NOOP {0x5}\r\nhello\r\n",
		"a NOOP {99999999999}\r\n",
		"a NOOP\nb DELETE x\r\n",
		"a NOOP\rb DELETE x\r\n",
		"a NOOP\x00\r\n",
		"a SEARCH SUBJECT {20000+}\r\n" + strings.Repeat("x", 20000) + "\r\n",
		"a NOOP " + strings.Repeat("x", 9000) + "\r\n",
	} {
		_, err := imapwire.ReadCommand(bufio.NewReader(strings.NewReader(raw)), imapwire.DefaultLimits, nil)
		if !errors.Is(err, imapwire.ErrFatal) {
			t.Errorf("%q: want fatal error, got %v", raw[:min(len(raw), 40)], err)
		}
	}
}

// upstreamVerbs is the complete set of commands the proxy may send upstream
// on behalf of a client.
var upstreamVerbs = map[string]bool{
	"EXAMINE": true, "STATUS": true, "LIST": true, "LSUB": true, "NAMESPACE": true,
	"NOOP": true, "IDLE": true, "UNSELECT": true, "CLOSE": true,
	"FETCH": true, "SEARCH": true, "UID FETCH": true, "UID SEARCH": true,
}

// checkInvariant verifies that an accepted command produces an upstream
// command that (1) uses an allowlisted verb, (2) is a canonical fixpoint and
// (3) never contains a non-PEEK body fetch.
func checkInvariant(t testing.TB, raw string, st State) {
	req, rej, err := parseRaw(t, raw, st)
	if err != nil || rej != nil || req.Upstream == nil {
		return
	}
	enc := wire(req.Upstream)
	again, rej2, err := parseRaw(t, "X "+enc, Selected)
	if err != nil || rej2 != nil {
		t.Fatalf("canonical form of %q does not re-parse: %q (%v %+v)", raw, enc, err, rej2)
	}
	if enc2 := wire(again.Upstream); enc2 != enc {
		t.Fatalf("canonical form is not a fixpoint:\n%q\n%q", enc, enc2)
	}
	rc, _ := imapwire.ReadCommand(bufio.NewReader(strings.NewReader("X "+enc)), imapwire.DefaultLimits, nil)
	toks, _ := imapwire.Tokenize(rc)
	verb := strings.ToUpper(string(toks[1].Value))
	if verb == "UID" {
		verb += " " + strings.ToUpper(string(toks[2].Value))
	}
	if !upstreamVerbs[verb] {
		t.Fatalf("non-allowlisted upstream verb %q from %q", verb, raw)
	}
	if strings.HasSuffix(verb, "FETCH") {
		for _, tok := range toks {
			if tok.Kind == imapwire.TokWord && strings.HasPrefix(strings.ToUpper(string(tok.Value)), "BODY[") {
				t.Fatalf("non-PEEK body fetch in %q", enc)
			}
		}
	}
}

func FuzzPolicy(f *testing.F) {
	for _, s := range []string{
		"a FETCH 1 BODY[]\r\n", "a UID FETCH 1:* (BODY[HEADER.FIELDS (A B)]<0.5> FLAGS)\r\n",
		"a SEARCH OR (FROM {3+}\r\nabc) NOT TEXT \"x\"\r\n", "a SELECT INBOX\r\n",
		"a STATUS {5+}\r\nINBOX (MESSAGES)\r\n", "a LIST \"\" {1+}\r\n*\r\n", "a IDLE\r\n",
		"a NOOP {+18}\r\nb1 DELETE Drafts\r\n", "a STORE 1 +FLAGS (\\Seen)\r\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		checkInvariant(t, raw, Selected)
		checkInvariant(t, raw, Authenticated)
	})
}

func TestInvariantOnAllowed(t *testing.T) {
	checkInvariant(t, "a UID FETCH 1:* (BODY[HEADER.FIELDS (\"A B\" C)]<0.5> FLAGS)\r\n", Selected)
	checkInvariant(t, "a SEARCH OR (FROM {3+}\r\nabc) NOT TEXT \"x\\\"y\"\r\n", Selected)
}
