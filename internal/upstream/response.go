package upstream

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// MaxResponseLine bounds a single response line from the upstream server.
const MaxResponseLine = 1 << 20

// MaxBufferedResponse bounds responses that must be fully buffered before
// forwarding (LIST/LSUB, for folder filtering).
const MaxBufferedResponse = 256 << 10

// ErrProtocol is returned when the upstream violates the protocol in a way
// that makes further framing unreliable.
var ErrProtocol = errors.New("upstream protocol error")

// Kind classifies an upstream response.
type Kind int

const (
	Untagged Kind = iota
	Tagged
	Continuation
)

// readLine reads one CRLF-terminated line including the CRLF.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > MaxResponseLine {
			return nil, fmt.Errorf("%w: response line too long", ErrProtocol)
		}
		buf = append(buf, chunk...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
	if len(buf) < 2 || buf[len(buf)-2] != '\r' {
		return nil, fmt.Errorf("%w: line not terminated by CRLF", ErrProtocol)
	}
	return buf, nil
}

// trailingLiteral returns the literal size if line (with CRLF) ends with a
// literal marker "{N}".
func trailingLiteral(line []byte) (int64, bool) {
	l := bytes.TrimSuffix(line, []byte("\r\n"))
	if len(l) < 3 || l[len(l)-1] != '}' {
		return 0, false
	}
	open := bytes.LastIndexByte(l, '{')
	if open < 0 {
		return 0, false
	}
	digits := l[open+1 : len(l)-1]
	if len(digits) == 0 || len(digits) > 12 {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(string(digits), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Response describes the first line of an upstream response.
type Response struct {
	Kind Kind
	Tag  string // for Tagged
	// First is the first line including CRLF.
	First []byte
	// HasMore is true if the first line ends with a literal and the rest
	// of the response must still be consumed via Stream or Buffer.
	HasMore bool
	litLen  int64
}

func classify(line []byte) (Kind, string) {
	switch {
	case bytes.HasPrefix(line, []byte("+ ")) || bytes.Equal(line, []byte("+\r\n")):
		return Continuation, ""
	case bytes.HasPrefix(line, []byte("* ")):
		return Untagged, ""
	}
	sp := bytes.IndexByte(line, ' ')
	if sp <= 0 {
		return Tagged, ""
	}
	return Tagged, string(line[:sp])
}

// ReadResponseStart reads the first line of the next response.
func ReadResponseStart(r *bufio.Reader) (*Response, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	kind, tag := classify(line)
	resp := &Response{Kind: kind, Tag: tag, First: line}
	if n, ok := trailingLiteral(line); ok {
		if kind != Untagged {
			return nil, fmt.Errorf("%w: literal in non-untagged response", ErrProtocol)
		}
		resp.HasMore = true
		resp.litLen = n
	}
	return resp, nil
}

// Stream copies the remainder of a response (literals and continuation
// lines) to w. The first line must already have been handled by the caller.
func (resp *Response) Stream(r *bufio.Reader, w io.Writer) error {
	n := resp.litLen
	for resp.HasMore {
		if _, err := io.CopyN(w, r, n); err != nil {
			return err
		}
		line, err := readLine(r)
		if err != nil {
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		n, resp.HasMore = trailingLiteral(line)
	}
	return nil
}

// Buffer reads the full response (including the first line) into memory,
// bounded by MaxBufferedResponse.
func (resp *Response) Buffer(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(resp.First)
	lw := &limitedWriter{w: &buf, n: MaxBufferedResponse}
	if err := resp.Stream(r, lw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, fmt.Errorf("%w: buffered response too large", ErrProtocol)
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}
