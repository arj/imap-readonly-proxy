package policy

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/arj/imap-readonly-proxy/internal/imapwire"
)

const maxSearchDepth = 16
const maxSearchKeys = 128

type searchArity int

const (
	argNone searchArity = iota
	argString
	argTwoStrings
	argDate
	argNumber
	argFlag
	argSeqSet
)

var searchKeys = map[string]searchArity{
	"ALL": argNone, "ANSWERED": argNone, "DELETED": argNone, "DRAFT": argNone,
	"FLAGGED": argNone, "NEW": argNone, "OLD": argNone, "RECENT": argNone,
	"SEEN": argNone, "UNANSWERED": argNone, "UNDELETED": argNone,
	"UNDRAFT": argNone, "UNFLAGGED": argNone, "UNSEEN": argNone,
	"BCC": argString, "BODY": argString, "CC": argString, "FROM": argString,
	"SUBJECT": argString, "TEXT": argString, "TO": argString,
	"HEADER": argTwoStrings,
	"BEFORE": argDate, "ON": argDate, "SINCE": argDate,
	"SENTBEFORE": argDate, "SENTON": argDate, "SENTSINCE": argDate,
	"LARGER": argNumber, "SMALLER": argNumber,
	"KEYWORD": argFlag, "UNKEYWORD": argFlag,
	"UID": argSeqSet,
}

var dateRe = regexp.MustCompile(`^([1-9]|[0-2][0-9]|3[01])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-[0-9]{4}$`)

func (p *parser) search(uid bool) (*Request, *Reject) {
	verb := "SEARCH"
	if uid {
		verb = "UID SEARCH"
	}
	b := new(imapwire.Builder)
	if uid {
		b.Atom("UID ")
	}
	b.Atom("SEARCH")

	if t, ok := p.peek(); ok && t.Kind == imapwire.TokWord && strings.EqualFold(string(t.Value), "CHARSET") {
		p.next()
		cs, ok := p.astring()
		if !ok {
			return nil, bad(p.tag, "Invalid CHARSET")
		}
		charset := strings.ToUpper(string(cs))
		if charset != "UTF-8" && charset != "US-ASCII" {
			return nil, no(p.tag, "[BADCHARSET (UTF-8 US-ASCII)] Unsupported charset")
		}
		b.Atom(" CHARSET ").Atom(charset)
	}
	if t, ok := p.peek(); ok && t.Kind == imapwire.TokWord && strings.EqualFold(string(t.Value), "RETURN") {
		return nil, bad(p.tag, "SEARCH RETURN is not supported")
	}
	if !p.more() {
		return nil, bad(p.tag, "Missing search criteria")
	}
	count := 0
	for p.more() {
		b.SP()
		if rej := p.searchKey(b, 0, &count); rej != nil {
			return nil, rej
		}
	}
	return &Request{Tag: p.tag, Verb: verb, Action: ActSearch, Upstream: b.Parts()}, nil
}

func (p *parser) searchKey(b *imapwire.Builder, depth int, count *int) *Reject {
	*count++
	if depth > maxSearchDepth || *count > maxSearchKeys {
		return bad(p.tag, "Search criteria too complex")
	}
	t, ok := p.next()
	if !ok {
		return bad(p.tag, "Incomplete search criteria")
	}
	if t.Kind == imapwire.TokOpen {
		b.Atom("(")
		n := 0
		for {
			nt, ok := p.peek()
			if !ok {
				return bad(p.tag, "Unterminated search group")
			}
			if nt.Kind == imapwire.TokClose {
				p.next()
				break
			}
			if n > 0 {
				b.SP()
			}
			if rej := p.searchKey(b, depth+1, count); rej != nil {
				return rej
			}
			n++
		}
		if n == 0 {
			return bad(p.tag, "Empty search group")
		}
		b.Atom(")")
		return nil
	}
	if t.Kind != imapwire.TokWord {
		return bad(p.tag, "Invalid search key")
	}
	key := strings.ToUpper(string(t.Value))
	switch key {
	case "NOT":
		b.Atom("NOT ")
		return p.searchKey(b, depth+1, count)
	case "OR":
		b.Atom("OR ")
		if rej := p.searchKey(b, depth+1, count); rej != nil {
			return rej
		}
		b.SP()
		return p.searchKey(b, depth+1, count)
	}
	arity, known := searchKeys[key]
	if !known {
		if validSeqSet(string(t.Value)) {
			b.Atom(string(t.Value))
			return nil
		}
		return bad(p.tag, "Unsupported search key")
	}
	b.Atom(key)
	switch arity {
	case argNone:
	case argString:
		v, ok := p.searchString()
		if !ok {
			return bad(p.tag, "Invalid search string")
		}
		b.SP().String(v)
	case argTwoStrings:
		f, ok1 := p.searchString()
		v, ok2 := p.searchString()
		if !ok1 || !ok2 || !validFieldName(f) {
			return bad(p.tag, "Invalid HEADER search")
		}
		b.SP().String(f).SP().String(v)
	case argDate:
		v, ok := p.astring()
		if !ok || !dateRe.Match(v) {
			return bad(p.tag, "Invalid search date")
		}
		b.SP().Atom(string(v))
	case argNumber:
		t, ok := p.next()
		if !ok || t.Kind != imapwire.TokWord || !validNumber(string(t.Value)) {
			return bad(p.tag, "Invalid search number")
		}
		b.SP().Atom(string(t.Value))
	case argFlag:
		t, ok := p.next()
		if !ok || t.Kind != imapwire.TokWord || !validKeyword(t.Value) {
			return bad(p.tag, "Invalid keyword")
		}
		b.SP().Atom(string(t.Value))
	case argSeqSet:
		t, ok := p.next()
		if !ok || t.Kind != imapwire.TokWord || !validSeqSet(string(t.Value)) {
			return bad(p.tag, "Invalid UID set")
		}
		b.SP().Atom(string(t.Value))
	}
	return nil
}

func (p *parser) searchString() ([]byte, bool) {
	t, ok := p.next()
	if !ok || !t.IsAString() || len(t.Value) > 1024 || !utf8.Valid(t.Value) {
		return nil, false
	}
	for _, c := range t.Value {
		if c < 0x20 && c != '\t' {
			return nil, false
		}
	}
	return t.Value, true
}

// validKeyword checks a flag keyword (ATOM-CHAR only, optional leading '\'
// is not allowed for KEYWORD per RFC 3501).
func validKeyword(v []byte) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
		switch c {
		case '(', ')', '{', '%', '*', '"', '\\', ']':
			return false
		}
	}
	return true
}
