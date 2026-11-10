package policy

import (
	"strconv"
	"strings"

	"github.com/arj/imap-readonly-proxy/internal/imapwire"
)

// validSeqSet validates an RFC 3501 sequence-set.
func validSeqSet(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, elem := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(elem, ":")
		if !validSeqNum(lo) || (isRange && !validSeqNum(hi)) {
			return false
		}
	}
	return true
}

func validSeqNum(s string) bool {
	if s == "*" {
		return true
	}
	return validNzNumber(s)
}

func validNzNumber(s string) bool {
	if s == "" || len(s) > 10 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return err == nil && v > 0
}

func validNumber(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// Fetch attributes that never change state.
var simpleFetchAtts = map[string]bool{
	"ENVELOPE": true, "FLAGS": true, "INTERNALDATE": true, "RFC822.HEADER": true,
	"RFC822.SIZE": true, "BODY": true, "BODYSTRUCTURE": true, "UID": true,
}

var fetchMacros = map[string]bool{"ALL": true, "FAST": true, "FULL": true}

func (p *parser) fetch(uid bool) (*Request, *Reject) {
	verb := "FETCH"
	if uid {
		verb = "UID FETCH"
	}
	t, ok := p.next()
	if !ok || t.Kind != imapwire.TokWord || !validSeqSet(string(t.Value)) {
		return nil, bad(p.tag, "Invalid sequence set")
	}
	b := new(imapwire.Builder)
	if uid {
		b.Atom("UID ")
	}
	b.Atom("FETCH ").Atom(string(t.Value)).SP()

	t, ok = p.peek()
	if !ok {
		return nil, bad(p.tag, "Missing fetch attributes")
	}
	if t.Kind == imapwire.TokWord && fetchMacros[strings.ToUpper(string(t.Value))] {
		p.next()
		b.Atom(strings.ToUpper(string(t.Value)))
	} else if t.Kind == imapwire.TokOpen {
		p.next()
		b.Atom("(")
		n := 0
		for {
			t, ok := p.peek()
			if !ok {
				return nil, bad(p.tag, "Unterminated fetch attribute list")
			}
			if t.Kind == imapwire.TokClose {
				p.next()
				break
			}
			if n > 0 {
				b.SP()
			}
			if rej := p.fetchAtt(b); rej != nil {
				return nil, rej
			}
			n++
			if n > 64 {
				return nil, bad(p.tag, "Too many fetch attributes")
			}
		}
		if n == 0 {
			return nil, bad(p.tag, "Empty fetch attribute list")
		}
		b.Atom(")")
	} else {
		if rej := p.fetchAtt(b); rej != nil {
			return nil, rej
		}
	}
	if p.more() {
		// FETCH modifiers (CHANGEDSINCE, ...) are not supported.
		return nil, bad(p.tag, "Unexpected arguments after fetch attributes")
	}
	return &Request{Tag: p.tag, Verb: verb, Action: ActFetch, Upstream: b.Parts()}, nil
}

// fetchAtt parses one fetch attribute and writes its canonical, side-effect
// free form. BODY[...] is always rewritten to BODY.PEEK[...]; the response
// item name is identical, so this is transparent to clients.
func (p *parser) fetchAtt(b *imapwire.Builder) *Reject {
	t, ok := p.next()
	if !ok || t.Kind != imapwire.TokWord {
		return bad(p.tag, "Invalid fetch attribute")
	}
	w := strings.ToUpper(string(t.Value))
	if simpleFetchAtts[w] {
		b.Atom(w)
		return nil
	}
	switch w {
	case "RFC822", "RFC822.TEXT":
		// These set \Seen and have no PEEK variant with the same
		// response name.
		return no(p.tag, "[NOPERM] Read-only proxy: use BODY.PEEK[] or BODY.PEEK[TEXT] instead of "+w)
	}
	var rest string
	switch {
	case strings.HasPrefix(w, "BODY.PEEK["):
		rest = string(t.Value[len("BODY.PEEK["):])
	case strings.HasPrefix(w, "BODY["):
		rest = string(t.Value[len("BODY["):])
	default:
		return bad(p.tag, "Unsupported fetch attribute")
	}

	b.Atom("BODY.PEEK[")
	section, after, closed := strings.Cut(rest, "]")
	text, needsList, valid := canonicalSection(section)
	if !valid {
		return bad(p.tag, "Invalid body section")
	}
	b.Atom(text)
	if needsList {
		if closed {
			return bad(p.tag, "HEADER.FIELDS requires a field list")
		}
		if t, ok := p.next(); !ok || t.Kind != imapwire.TokOpen {
			return bad(p.tag, "HEADER.FIELDS requires a field list")
		}
		b.Atom(" (")
		n := 0
		for {
			t, ok := p.next()
			if !ok {
				return bad(p.tag, "Unterminated header list")
			}
			if t.Kind == imapwire.TokClose {
				break
			}
			if !t.IsAString() || !validFieldName(t.Value) || n >= 128 {
				return bad(p.tag, "Invalid header field name")
			}
			if n > 0 {
				b.SP()
			}
			b.AString(t.Value)
			n++
		}
		if n == 0 {
			return bad(p.tag, "Empty header list")
		}
		b.Atom(")")
		t, ok := p.next()
		if !ok || t.Kind != imapwire.TokWord || t.Value[0] != ']' {
			return bad(p.tag, "Invalid body section")
		}
		after = string(t.Value[1:])
	} else if !closed {
		return bad(p.tag, "Invalid body section")
	}
	b.Atom("]")
	if after != "" {
		if !validPartial(after) {
			return bad(p.tag, "Invalid partial specifier")
		}
		b.Atom(after)
	}
	return nil
}

// canonicalSection validates a section-spec (without brackets) and returns
// its canonical upper-case form and whether a header list must follow.
func canonicalSection(s string) (string, bool, bool) {
	if s == "" {
		return "", false, true
	}
	if len(s) > 256 {
		return "", false, false
	}
	parts := strings.Split(strings.ToUpper(s), ".")
	i := 0
	for i < len(parts) && parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
		if !validNzNumber(parts[i]) {
			return "", false, false
		}
		i++
	}
	nums := parts[:i]
	textPart := strings.Join(parts[i:], ".")
	if len(nums) > 32 {
		return "", false, false
	}
	needsList := false
	switch textPart {
	case "":
		if len(nums) == 0 {
			return "", false, false
		}
	case "HEADER", "TEXT":
	case "HEADER.FIELDS", "HEADER.FIELDS.NOT":
		needsList = true
	case "MIME":
		if len(nums) == 0 {
			return "", false, false
		}
	default:
		return "", false, false
	}
	out := strings.Join(nums, ".")
	if textPart != "" {
		if out != "" {
			out += "."
		}
		out += textPart
	}
	return out, needsList, true
}

func validPartial(s string) bool {
	if len(s) < 5 || s[0] != '<' || s[len(s)-1] != '>' {
		return false
	}
	off, cnt, ok := strings.Cut(s[1:len(s)-1], ".")
	return ok && validNumber(off) && validNzNumber(cnt)
}

// validFieldName checks an RFC 5322 field name (printable ASCII except ':').
func validFieldName(v []byte) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if c <= 0x20 || c >= 0x7f || c == ':' {
			return false
		}
	}
	return true
}
