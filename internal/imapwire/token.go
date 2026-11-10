package imapwire

// TokenKind identifies the lexical class of a token.
type TokenKind int

const (
	// TokWord is a run of printable ASCII characters that are not
	// separators. It covers atoms, numbers, sequence sets, flags and fetch
	// attributes such as "BODY.PEEK[1.2]<0.100>".
	TokWord TokenKind = iota
	// TokQuoted is a quoted string; Value holds the unescaped content.
	TokQuoted
	// TokLiteral is a literal; Value holds the raw octets.
	TokLiteral
	// TokOpen is "(".
	TokOpen
	// TokClose is ")".
	TokClose
)

// Token is a lexical element of a client command.
type Token struct {
	Kind  TokenKind
	Value []byte
}

// IsString reports whether the token is an IMAP string (quoted or literal).
func (t Token) IsString() bool { return t.Kind == TokQuoted || t.Kind == TokLiteral }

// IsAString reports whether the token can be used as an astring.
func (t Token) IsAString() bool { return t.Kind == TokWord || t.IsString() }

func isWordChar(c byte) bool {
	if c <= 0x20 || c >= 0x7f {
		return false
	}
	switch c {
	case '(', ')', '"', '{':
		return false
	}
	return true
}

// Tokenize splits a raw command into tokens. Tokens must be separated by
// exactly one space, except around parentheses, mirroring RFC 3501.
func Tokenize(rc *RawCommand) ([]Token, error) {
	var toks []Token
	for si, seg := range rc.Segments {
		text := seg.Text
		if seg.HasLiteral {
			// Strip the literal marker; it is replaced by a literal token.
			open := lastIndex(text, '{')
			text = text[:open]
		}
		i := 0
		for i < len(text) {
			c := text[i]
			switch {
			case c == ' ':
				if i+1 < len(text) && text[i+1] == ' ' {
					return nil, syntaxErr("unexpected double space")
				}
				i++
			case c == '(':
				toks = append(toks, Token{Kind: TokOpen})
				i++
			case c == ')':
				toks = append(toks, Token{Kind: TokClose})
				i++
			case c == '"':
				val, n, err := scanQuoted(text[i:])
				if err != nil {
					return nil, err
				}
				toks = append(toks, Token{Kind: TokQuoted, Value: val})
				i += n
			case isWordChar(c):
				j := i
				for j < len(text) && isWordChar(text[j]) {
					j++
				}
				toks = append(toks, Token{Kind: TokWord, Value: text[i:j]})
				i = j
			default:
				return nil, syntaxErr("invalid character 0x%02x", c)
			}
		}
		if seg.HasLiteral {
			if len(text) > 0 && text[len(text)-1] != ' ' && text[len(text)-1] != '(' {
				return nil, syntaxErr("literal must follow a space or '('")
			}
			toks = append(toks, Token{Kind: TokLiteral, Value: seg.Literal})
			// The next segment must continue with a separator or ")".
			if si+1 < len(rc.Segments) {
				next := rc.Segments[si+1].Text
				if len(next) > 0 && next[0] != ' ' && next[0] != ')' {
					return nil, syntaxErr("missing space after literal")
				}
			}
		}
	}
	return toks, nil
}

func lastIndex(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// scanQuoted parses a quoted string at the start of b and returns the
// unescaped value and the number of bytes consumed. Only \" and \\ escapes
// are valid (RFC 3501 quoted-specials).
func scanQuoted(b []byte) ([]byte, int, error) {
	var out []byte
	i := 1
	for i < len(b) {
		c := b[i]
		switch c {
		case '\\':
			if i+1 >= len(b) || (b[i+1] != '"' && b[i+1] != '\\') {
				return nil, 0, syntaxErr("invalid escape in quoted string")
			}
			out = append(out, b[i+1])
			i += 2
		case '"':
			if i+1 < len(b) && b[i+1] != ' ' && b[i+1] != ')' {
				return nil, 0, syntaxErr("missing space after quoted string")
			}
			if out == nil {
				out = []byte{}
			}
			return out, i + 1, nil
		default:
			out = append(out, c)
			i++
		}
	}
	return nil, 0, syntaxErr("unterminated quoted string")
}
