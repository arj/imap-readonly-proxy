package restapi

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// value is a parsed item of IMAP response data.
type value struct {
	kind  valueKind
	bytes []byte  // atom text or string content
	list  []value // for kindList
}

type valueKind int

const (
	kindAtom valueKind = iota
	kindString
	kindNil
	kindList
)

func (v value) isString() bool { return v.kind == kindString }

// str returns the string content of a string or atom, "" for NIL.
func (v value) str() string {
	if v.kind == kindString || v.kind == kindAtom {
		return string(v.bytes)
	}
	return ""
}

func (v value) atomIs(s string) bool {
	return v.kind == kindAtom && strings.EqualFold(string(v.bytes), s)
}

func (v value) number() (uint64, bool) {
	if v.kind != kindAtom {
		return 0, false
	}
	n, err := strconv.ParseUint(string(v.bytes), 10, 64)
	return n, err == nil
}

var errSyntax = errors.New("malformed upstream response")

const maxDepth = 32

// parseResponse parses a complete, buffered untagged response (as returned
// by upstream.Response.Buffer) after the leading "* ". Literals are
// embedded as "{N}\r\n" followed by N bytes.
func parseResponse(b []byte) ([]value, error) {
	if !bytes.HasPrefix(b, []byte("* ")) {
		return nil, errSyntax
	}
	p := &sparser{b: b, pos: 2}
	var out []value
	for {
		if p.atEnd() {
			return out, nil
		}
		v, err := p.item(0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if p.atEnd() {
			return out, nil
		}
		if err := p.sp(); err != nil {
			return nil, err
		}
	}
}

type sparser struct {
	b   []byte
	pos int
}

func (p *sparser) atEnd() bool {
	return bytes.Equal(p.b[p.pos:], []byte("\r\n"))
}

func (p *sparser) sp() error {
	if p.pos >= len(p.b) || p.b[p.pos] != ' ' {
		return errSyntax
	}
	p.pos++
	return nil
}

func (p *sparser) item(depth int) (value, error) {
	if depth > maxDepth || p.pos >= len(p.b) {
		return value{}, errSyntax
	}
	switch c := p.b[p.pos]; c {
	case '(':
		p.pos++
		var l []value
		for {
			if p.pos >= len(p.b) {
				return value{}, errSyntax
			}
			if p.b[p.pos] == ')' {
				p.pos++
				return value{kind: kindList, list: l}, nil
			}
			if len(l) > 0 {
				if err := p.sp(); err != nil {
					return value{}, err
				}
			}
			v, err := p.item(depth + 1)
			if err != nil {
				return value{}, err
			}
			l = append(l, v)
		}
	case '"':
		p.pos++
		var s []byte
		for p.pos < len(p.b) {
			c := p.b[p.pos]
			switch c {
			case '\\':
				if p.pos+1 >= len(p.b) {
					return value{}, errSyntax
				}
				s = append(s, p.b[p.pos+1])
				p.pos += 2
			case '"':
				p.pos++
				return value{kind: kindString, bytes: s}, nil
			case '\r', '\n':
				return value{}, errSyntax
			default:
				s = append(s, c)
				p.pos++
			}
		}
		return value{}, errSyntax
	case '{':
		end := bytes.Index(p.b[p.pos:], []byte("}\r\n"))
		if end < 0 {
			return value{}, errSyntax
		}
		n, err := strconv.Atoi(string(p.b[p.pos+1 : p.pos+end]))
		if err != nil || n < 0 {
			return value{}, errSyntax
		}
		start := p.pos + end + 3
		if start+n > len(p.b) {
			return value{}, errSyntax
		}
		p.pos = start + n
		return value{kind: kindString, bytes: p.b[start : start+n]}, nil
	default:
		// Atom; brackets (as in BODY[HEADER.FIELDS (A B)]) may contain
		// spaces and parentheses.
		start := p.pos
		for p.pos < len(p.b) {
			c := p.b[p.pos]
			if c == '[' {
				end := bytes.IndexByte(p.b[p.pos:], ']')
				if end < 0 {
					return value{}, errSyntax
				}
				p.pos += end + 1
				continue
			}
			if c == ' ' || c == '(' || c == ')' || c == '\r' || c == '\n' || c == '"' || c == '{' {
				break
			}
			p.pos++
		}
		if p.pos == start {
			return value{}, errSyntax
		}
		a := p.b[start:p.pos]
		if strings.EqualFold(string(a), "NIL") {
			return value{kind: kindNil}, nil
		}
		return value{kind: kindAtom, bytes: a}, nil
	}
}
