package restapi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// Limits for MIME processing.
const (
	maxMIMEDepth = 10
	maxMIMEParts = 500
)

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return nil, fmt.Errorf("unsupported charset %q", charset)
	}
	return enc.NewDecoder().Reader(input), nil
}

// toUTF8 converts text in the given charset to valid UTF-8.
func toUTF8(b []byte, charset string) string {
	if charset != "" && !strings.EqualFold(charset, "utf-8") && !strings.EqualFold(charset, "us-ascii") {
		if r, err := charsetReader(charset, bytes.NewReader(b)); err == nil {
			if out, err := io.ReadAll(r); err == nil {
				b = out
			}
		}
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// Address is a decoded mailbox address.
type Address struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

func decodeHeader(v string) string {
	d, err := wordDecoder.DecodeHeader(v)
	if err != nil {
		d = v
	}
	return strings.ToValidUTF8(d, "\uFFFD")
}

func parseAddresses(v string) []Address {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	p := mail.AddressParser{WordDecoder: wordDecoder}
	list, err := p.ParseList(v)
	if err != nil {
		// Keep the information, unparsed.
		return []Address{{Name: decodeHeader(v)}}
	}
	out := make([]Address, 0, len(list))
	for _, a := range list {
		out = append(out, Address{Name: strings.ToValidUTF8(a.Name, "\uFFFD"), Address: strings.ToValidUTF8(a.Address, "\uFFFD")})
	}
	return out
}

// Envelope holds the commonly used header fields.
type Envelope struct {
	Subject   string    `json:"subject"`
	From      []Address `json:"from,omitempty"`
	To        []Address `json:"to,omitempty"`
	Cc        []Address `json:"cc,omitempty"`
	ReplyTo   []Address `json:"reply_to,omitempty"`
	Date      string    `json:"date,omitempty"` // RFC 3339 if parseable, else raw
	MessageID string    `json:"message_id,omitempty"`
	InReplyTo string    `json:"in_reply_to,omitempty"`
}

// envelopeHeaderFields are fetched for message lists.
var envelopeHeaderFields = []string{"From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "In-Reply-To"}

func envelopeFrom(h mail.Header) Envelope {
	e := Envelope{
		Subject:   decodeHeader(h.Get("Subject")),
		From:      parseAddresses(h.Get("From")),
		To:        parseAddresses(h.Get("To")),
		Cc:        parseAddresses(h.Get("Cc")),
		ReplyTo:   parseAddresses(h.Get("Reply-To")),
		MessageID: strings.ToValidUTF8(strings.TrimSpace(h.Get("Message-ID")), "\uFFFD"),
		InReplyTo: strings.ToValidUTF8(strings.TrimSpace(h.Get("In-Reply-To")), "\uFFFD"),
	}
	if d := h.Get("Date"); d != "" {
		if t, err := mail.ParseDate(d); err == nil {
			e.Date = t.Format(time.RFC3339)
		} else {
			e.Date = decodeHeader(d)
		}
	}
	return e
}

// parseHeaderBlock parses a header block as returned by
// BODY.PEEK[HEADER.FIELDS (...)].
func parseHeaderBlock(b []byte) mail.Header {
	if !bytes.HasSuffix(b, []byte("\r\n\r\n")) && !bytes.HasSuffix(b, []byte("\n\n")) {
		b = append(append([]byte(nil), b...), "\r\n\r\n"...)
	}
	m, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		return mail.Header{}
	}
	return m.Header
}

// Attachment describes a non-body MIME part.
type Attachment struct {
	Index       int    `json:"index"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"` // decoded size in bytes
	Inline      bool   `json:"inline,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
}

// Parsed is a decoded message.
type Parsed struct {
	Envelope    Envelope
	Text        string
	HTML        string
	Attachments []Attachment
	// data holds decoded attachment contents, by index.
	data [][]byte
}

var errMIMELimit = errors.New("MIME structure too complex")

// parseMessage decodes a full RFC 5322 message.
func parseMessage(raw []byte) (*Parsed, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}
	p := &Parsed{Envelope: envelopeFrom(m.Header)}
	parts := 0
	if err := p.walk(textproto.MIMEHeader(m.Header), m.Body, 0, &parts); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeTransfer(h textproto.MIMEHeader, body io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &base64Cleaner{r: body})
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	default:
		return body
	}
}

// base64Cleaner drops whitespace so line-wrapped base64 decodes.
type base64Cleaner struct{ r io.Reader }

func (c *base64Cleaner) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	j := 0
	for _, b := range p[:n] {
		if b != '\r' && b != '\n' && b != ' ' && b != '\t' {
			p[j] = b
			j++
		}
	}
	return j, err
}

func (p *Parsed) walk(h textproto.MIMEHeader, body io.Reader, depth int, parts *int) error {
	*parts++
	if depth > maxMIMEDepth || *parts > maxMIMEParts {
		return errMIMELimit
	}
	ct := h.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || ct == "" {
		mediaType, params = "text/plain", map[string]string{}
	}
	mediaType = strings.ToLower(mediaType)
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	disp = strings.ToLower(disp)
	filename := dparams["filename"]
	if filename == "" {
		filename = params["name"]
	}
	filename = strings.ToValidUTF8(decodeHeader(filename), "\uFFFD")

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return nil
		}
		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextRawPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				// Truncated or malformed multipart: keep what was decoded.
				return nil
			}
			if err := p.walk(part.Header, part, depth+1, parts); err != nil {
				return err
			}
		}
	}

	data, err := io.ReadAll(decodeTransfer(h, body))
	if err != nil {
		// Corrupt transfer encoding; keep partial data.
		data = append([]byte(nil), data...)
	}
	isBody := disp != "attachment" && filename == ""
	switch {
	case isBody && mediaType == "text/plain" && p.Text == "":
		p.Text = toUTF8(data, params["charset"])
		return nil
	case isBody && mediaType == "text/html" && p.HTML == "":
		p.HTML = toUTF8(data, params["charset"])
		return nil
	}
	if mediaType == "message/rfc822" && disp != "attachment" && filename == "" {
		filename = "message.eml"
	}
	if !utf8.ValidString(filename) {
		filename = ""
	}
	p.Attachments = append(p.Attachments, Attachment{
		Index:       len(p.Attachments),
		Filename:    filename,
		ContentType: mediaType,
		Size:        len(data),
		Inline:      disp == "inline",
		ContentID:   strings.Trim(strings.TrimSpace(h.Get("Content-ID")), "<>"),
	})
	p.data = append(p.data, data)
	return nil
}
