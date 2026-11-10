package imapwire

import "strconv"

// Part is one piece of an outgoing command: either protocol text or a
// literal payload. Text never contains a literal marker; the sender emits
// the marker itself when it sends a literal part.
type Part struct {
	Text      []byte
	IsLiteral bool
	Literal   []byte
}

// Builder assembles a canonical upstream command from validated values.
// All text written through Atom must already be validated by the caller;
// strings are always re-encoded by String.
type Builder struct {
	parts []Part
	cur   []byte
}

// Atom appends protocol text verbatim. Callers must only pass values that
// were validated against a strict grammar (keywords, numbers, sets).
func (b *Builder) Atom(s string) *Builder {
	b.cur = append(b.cur, s...)
	return b
}

// SP appends a single space.
func (b *Builder) SP() *Builder {
	b.cur = append(b.cur, ' ')
	return b
}

// String appends s as a quoted string if it is printable ASCII, otherwise as
// a literal. The quoted form escapes '"' and '\'.
func (b *Builder) String(s []byte) *Builder {
	if isQuotable(s) {
		b.cur = append(b.cur, '"')
		for _, c := range s {
			if c == '"' || c == '\\' {
				b.cur = append(b.cur, '\\')
			}
			b.cur = append(b.cur, c)
		}
		b.cur = append(b.cur, '"')
		return b
	}
	b.parts = append(b.parts, Part{Text: b.cur})
	b.parts = append(b.parts, Part{IsLiteral: true, Literal: append([]byte(nil), s...)})
	b.cur = nil
	return b
}

// Number appends a decimal number.
func (b *Builder) Number(n uint64) *Builder {
	b.cur = strconv.AppendUint(b.cur, n, 10)
	return b
}

// Parts returns the finished command, terminated by CRLF.
func (b *Builder) Parts() []Part {
	out := append([]Part(nil), b.parts...)
	out = append(out, Part{Text: append(append([]byte(nil), b.cur...), '\r', '\n')})
	return out
}

func isQuotable(s []byte) bool {
	if len(s) > 1024 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// IsPrintableASCII reports whether s consists only of 0x20..0x7e.
func IsPrintableASCII(s []byte) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// AString appends s as an atom if every byte is an ATOM-CHAR (RFC 3501),
// and otherwise as a string. Clients often match response item names
// textually, so atoms are preserved as atoms.
func (b *Builder) AString(s []byte) *Builder {
	if isAtom(s) {
		b.cur = append(b.cur, s...)
		return b
	}
	return b.String(s)
}

func isAtom(s []byte) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
		switch c {
		case '(', ')', '{', '%', '*', '"', '\\', ']':
			return false
		}
	}
	// NIL would be read as the nil value, not as a string.
	return !(len(s) == 3 && (s[0]|0x20) == 'n' && (s[1]|0x20) == 'i' && (s[2]|0x20) == 'l')
}
