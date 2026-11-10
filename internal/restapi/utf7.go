package restapi

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Mailbox names on the wire use IMAP modified UTF-7 (RFC 3501 5.1.3). The
// REST API exposes and accepts UTF-8 names.

var utf7Enc = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)

var errUTF7 = errors.New("invalid modified UTF-7 mailbox name")

// decodeMailbox converts a modified UTF-7 name to UTF-8. It only accepts
// canonical encodings, so decode(encode(x)) == x and encode(decode(y)) == y.
func decodeMailbox(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return "", errUTF7
		}
		if c != '&' {
			b.WriteByte(c)
			i++
			continue
		}
		end := strings.IndexByte(s[i+1:], '-')
		if end < 0 {
			return "", errUTF7
		}
		enc := s[i+1 : i+1+end]
		i += end + 2
		if enc == "" {
			b.WriteByte('&')
			continue
		}
		raw, err := utf7Enc.DecodeString(enc)
		if err != nil || len(raw)%2 != 0 {
			return "", errUTF7
		}
		u := make([]uint16, len(raw)/2)
		for j := range u {
			u[j] = uint16(raw[2*j])<<8 | uint16(raw[2*j+1])
		}
		runes := utf16.Decode(u)
		for _, r := range runes {
			if r == utf8.RuneError || (r >= 0x20 && r <= 0x7e) {
				return "", errUTF7
			}
			b.WriteRune(r)
		}
	}
	out := b.String()
	if encodeMailbox(out) != s {
		return "", errUTF7
	}
	return out, nil
}

// encodeMailbox converts a UTF-8 name to modified UTF-7.
func encodeMailbox(s string) string {
	var b strings.Builder
	var pending []rune
	flush := func() {
		if len(pending) == 0 {
			return
		}
		u := utf16.Encode(pending)
		raw := make([]byte, 2*len(u))
		for j, v := range u {
			raw[2*j], raw[2*j+1] = byte(v>>8), byte(v)
		}
		b.WriteByte('&')
		b.WriteString(utf7Enc.EncodeToString(raw))
		b.WriteByte('-')
		pending = pending[:0]
	}
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			flush()
			if r == '&' {
				b.WriteString("&-")
			} else {
				b.WriteRune(r)
			}
			continue
		}
		pending = append(pending, r)
	}
	flush()
	return b.String()
}
