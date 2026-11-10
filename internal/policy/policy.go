// Package policy decides which client commands are permitted and translates
// each permitted command into a freshly encoded, canonical upstream command.
//
// The policy is an allowlist. Every command, sub-command, fetch attribute,
// status item and search key that is not explicitly listed here is rejected.
// Unknown or future IMAP extensions are therefore blocked by default.
package policy

import (
	"bytes"
	"strings"

	"github.com/arj/imap-readonly-proxy/internal/imapwire"
)

// State is the IMAP connection state as seen by the proxy.
type State int

const (
	NotAuthenticated State = iota
	Authenticated
	Selected
)

// Action is the operation the session must perform for a request.
type Action int

const (
	ActCapability Action = iota
	ActNoop
	ActLogout
	ActLogin
	ActExamine // SELECT and EXAMINE; always sent upstream as EXAMINE
	ActStatus  // STATUS
	ActList    // LIST and LSUB; responses are folder-filtered
	ActNamespace
	ActFetch
	ActSearch
	ActClose // CLOSE and UNSELECT; mailbox is read-only, nothing is expunged
	ActIdle
)

// UpstreamCaps are the upstream capabilities that change what the proxy
// can offer.
type UpstreamCaps struct {
	Idle      bool
	Unselect  bool
	Namespace bool
}

// Request is a validated client command.
type Request struct {
	Tag    string
	Verb   string // canonical client verb, for logging
	Action Action

	// Mailbox is the target mailbox for ActExamine and ActStatus.
	Mailbox string

	// User and Pass are set for ActLogin.
	User, Pass string

	// Upstream builds the upstream command after the upstream tag. It is nil
	// for actions handled locally.
	Upstream []imapwire.Part
}

// Reject describes a refused command.
type Reject struct {
	Tag  string // "*" if no valid tag was found
	Kind string // "BAD" or "NO"
	Text string
}

func bad(tag, text string) *Reject { return &Reject{Tag: tag, Kind: "BAD", Text: text} }
func no(tag, text string) *Reject  { return &Reject{Tag: tag, Kind: "NO", Text: text} }

// ValidTag reports whether tag is acceptable. Tags are restricted to a
// conservative character set so they can be echoed safely.
func ValidTag(tag []byte) bool {
	if len(tag) == 0 || len(tag) > 64 {
		return false
	}
	for _, c := range tag {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == ':' || c == '/' || c == '!' || c == '#' || c == '$' || c == '&' || c == '\'' || c == ',' || c == ';' || c == '<' || c == '=' || c == '>' || c == '?' || c == '@' || c == '^' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

// Parse validates a tokenized command for the given state and returns the
// request to execute, or a rejection.
func Parse(toks []imapwire.Token, st State, caps UpstreamCaps) (*Request, *Reject) {
	if len(toks) == 0 || toks[0].Kind != imapwire.TokWord || !ValidTag(toks[0].Value) {
		return nil, bad("*", "Invalid tag")
	}
	tag := string(toks[0].Value)
	if len(toks) < 2 || toks[1].Kind != imapwire.TokWord {
		return nil, bad(tag, "Missing command")
	}
	verb := strings.ToUpper(string(toks[1].Value))
	args := toks[2:]
	p := &parser{tag: tag, toks: args}

	// Commands valid in any state.
	switch verb {
	case "CAPABILITY":
		return p.noArgs(verb, ActCapability)
	case "NOOP":
		req, rej := p.noArgs(verb, ActNoop)
		if req != nil {
			req.Upstream = new(imapwire.Builder).Atom("NOOP").Parts()
		}
		return req, rej
	case "LOGOUT":
		return p.noArgs(verb, ActLogout)
	}

	if st == NotAuthenticated {
		if verb == "LOGIN" {
			return p.login()
		}
		return nil, bad(tag, "Command not permitted before login")
	}

	switch verb {
	case "SELECT", "EXAMINE":
		return p.examine(verb)
	case "STATUS":
		return p.status()
	case "LIST", "LSUB":
		return p.list(verb)
	case "NAMESPACE":
		if !caps.Namespace {
			return nil, bad(tag, "Command not supported")
		}
		req, rej := p.noArgs(verb, ActNamespace)
		if req != nil {
			req.Upstream = new(imapwire.Builder).Atom("NAMESPACE").Parts()
		}
		return req, rej
	case "IDLE":
		if !caps.Idle {
			return nil, bad(tag, "Command not supported")
		}
		req, rej := p.noArgs(verb, ActIdle)
		if req != nil {
			req.Upstream = new(imapwire.Builder).Atom("IDLE").Parts()
		}
		return req, rej
	}

	if st != Selected {
		if selectedVerbs[verb] {
			return nil, bad(tag, "No mailbox selected")
		}
		return nil, refuse(tag, verb)
	}

	switch verb {
	case "CLOSE", "UNSELECT":
		if verb == "UNSELECT" && !caps.Unselect {
			return nil, bad(tag, "Command not supported")
		}
		req, rej := p.noArgs(verb, ActClose)
		if req != nil {
			// The mailbox is always opened with EXAMINE, so CLOSE cannot
			// expunge (RFC 3501 6.4.2). Prefer UNSELECT when available so
			// this does not depend on the server honouring that rule.
			up := "CLOSE"
			if caps.Unselect {
				up = "UNSELECT"
			}
			req.Upstream = new(imapwire.Builder).Atom(up).Parts()
		}
		return req, rej
	case "FETCH":
		return p.fetch(false)
	case "SEARCH":
		return p.search(false)
	case "UID":
		if len(args) == 0 || args[0].Kind != imapwire.TokWord {
			return nil, bad(tag, "Missing UID command")
		}
		sub := strings.ToUpper(string(args[0].Value))
		p.toks = args[1:]
		switch sub {
		case "FETCH":
			return p.fetch(true)
		case "SEARCH":
			return p.search(true)
		}
		return nil, refuse(tag, "UID "+sub)
	}
	return nil, refuse(tag, verb)
}

var selectedVerbs = map[string]bool{
	"FETCH": true, "SEARCH": true, "UID": true, "CLOSE": true, "UNSELECT": true,
}

// knownWriteVerbs are answered with NO (instead of BAD) so clients show a
// clear "read-only" message. Everything else unknown is answered with BAD.
var knownWriteVerbs = map[string]bool{
	"STORE": true, "COPY": true, "MOVE": true, "EXPUNGE": true, "APPEND": true,
	"CREATE": true, "DELETE": true, "RENAME": true, "SUBSCRIBE": true,
	"UNSUBSCRIBE": true, "SETACL": true, "DELETEACL": true, "SETMETADATA": true,
	"SETQUOTA": true, "REPLACE": true, "UID STORE": true, "UID COPY": true,
	"UID MOVE": true, "UID EXPUNGE": true, "UID REPLACE": true,
}

func refuse(tag, verb string) *Reject {
	if knownWriteVerbs[verb] {
		return no(tag, "[NOPERM] Read-only proxy: "+verb+" is not permitted")
	}
	return bad(tag, "Command not supported by read-only proxy")
}

type parser struct {
	tag  string
	toks []imapwire.Token
	pos  int
}

func (p *parser) more() bool { return p.pos < len(p.toks) }

func (p *parser) next() (imapwire.Token, bool) {
	if p.pos >= len(p.toks) {
		return imapwire.Token{}, false
	}
	t := p.toks[p.pos]
	p.pos++
	return t, true
}

func (p *parser) peek() (imapwire.Token, bool) {
	if p.pos >= len(p.toks) {
		return imapwire.Token{}, false
	}
	return p.toks[p.pos], true
}

func (p *parser) noArgs(verb string, act Action) (*Request, *Reject) {
	if p.more() {
		return nil, bad(p.tag, verb+" takes no arguments")
	}
	return &Request{Tag: p.tag, Verb: verb, Action: act}, nil
}

// astring reads an astring and returns its value.
func (p *parser) astring() ([]byte, bool) {
	t, ok := p.next()
	if !ok || !t.IsAString() {
		return nil, false
	}
	if t.Kind == imapwire.TokWord && bytes.ContainsAny(t.Value, "%*") {
		// '%' and '*' are list-wildcards and are not ATOM-CHARs.
		return nil, false
	}
	return t.Value, true
}

// mailbox reads a mailbox name. Mailbox names are restricted to printable
// ASCII (IMAP4rev1 uses modified UTF-7), which makes policy checks on the
// name unambiguous.
func (p *parser) mailbox() (string, bool) {
	v, ok := p.astring()
	if !ok || len(v) == 0 || len(v) > 512 || !imapwire.IsPrintableASCII(v) {
		return "", false
	}
	return string(v), true
}

func (p *parser) login() (*Request, *Reject) {
	user, ok1 := p.astring()
	pass, ok2 := p.astring()
	if !ok1 || !ok2 || p.more() || len(user) > 256 || len(pass) > 1024 {
		return nil, bad(p.tag, "Invalid LOGIN arguments")
	}
	return &Request{Tag: p.tag, Verb: "LOGIN", Action: ActLogin, User: string(user), Pass: string(pass)}, nil
}

func (p *parser) examine(verb string) (*Request, *Reject) {
	mbox, ok := p.mailbox()
	if !ok || p.more() {
		// Select parameters (CONDSTORE, QRESYNC, ...) are not supported.
		return nil, bad(p.tag, "Invalid "+verb+" arguments")
	}
	b := new(imapwire.Builder).Atom("EXAMINE").SP().String([]byte(mbox))
	return &Request{Tag: p.tag, Verb: verb, Action: ActExamine, Mailbox: mbox, Upstream: b.Parts()}, nil
}

var statusItems = map[string]bool{
	"MESSAGES": true, "RECENT": true, "UIDNEXT": true, "UIDVALIDITY": true, "UNSEEN": true,
}

func (p *parser) status() (*Request, *Reject) {
	mbox, ok := p.mailbox()
	if !ok {
		return nil, bad(p.tag, "Invalid STATUS arguments")
	}
	if t, ok := p.next(); !ok || t.Kind != imapwire.TokOpen {
		return nil, bad(p.tag, "Invalid STATUS arguments")
	}
	b := new(imapwire.Builder).Atom("STATUS").SP().String([]byte(mbox)).SP().Atom("(")
	n := 0
	for {
		t, ok := p.next()
		if !ok {
			return nil, bad(p.tag, "Invalid STATUS arguments")
		}
		if t.Kind == imapwire.TokClose {
			break
		}
		item := strings.ToUpper(string(t.Value))
		if t.Kind != imapwire.TokWord || !statusItems[item] || n >= len(statusItems) {
			return nil, bad(p.tag, "Unsupported STATUS item")
		}
		if n > 0 {
			b.SP()
		}
		b.Atom(item)
		n++
	}
	if n == 0 || p.more() {
		return nil, bad(p.tag, "Invalid STATUS arguments")
	}
	b.Atom(")")
	return &Request{Tag: p.tag, Verb: "STATUS", Action: ActStatus, Mailbox: mbox, Upstream: b.Parts()}, nil
}

func (p *parser) list(verb string) (*Request, *Reject) {
	// Only the basic RFC 3501 form: LIST reference pattern.
	ref, ok1 := p.listMailbox(true)
	pat, ok2 := p.listMailbox(false)
	if !ok1 || !ok2 || p.more() {
		return nil, bad(p.tag, "Invalid "+verb+" arguments")
	}
	b := new(imapwire.Builder).Atom(verb).SP().String(ref).SP().String(pat)
	return &Request{Tag: p.tag, Verb: verb, Action: ActList, Upstream: b.Parts()}, nil
}

func (p *parser) listMailbox(allowEmpty bool) ([]byte, bool) {
	t, ok := p.next()
	if !ok || !t.IsAString() {
		return nil, false
	}
	v := t.Value
	if len(v) > 512 || !imapwire.IsPrintableASCII(v) {
		return nil, false
	}
	if len(v) == 0 && !allowEmpty && t.Kind == imapwire.TokWord {
		return nil, false
	}
	return v, true
}
