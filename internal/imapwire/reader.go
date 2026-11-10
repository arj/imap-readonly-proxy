// Package imapwire reads client commands and writes canonical upstream
// commands. It never hands raw client bytes to anything that writes upstream:
// the reader produces tokens, and the Builder produces fresh wire bytes.
package imapwire

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// Limits bound the resources a single client command may consume.
type Limits struct {
	MaxLine     int   // maximum bytes in one CRLF-terminated line
	MaxLiteral  int64 // maximum bytes in one literal
	MaxCommand  int64 // maximum total bytes of one command (lines + literals)
	MaxLiterals int   // maximum number of literals in one command
}

// DefaultLimits are conservative limits suitable for a read-only proxy.
// Read-only commands never need large client literals.
var DefaultLimits = Limits{
	MaxLine:     8 * 1024,
	MaxLiteral:  16 * 1024,
	MaxCommand:  64 * 1024,
	MaxLiterals: 16,
}

// ErrFatal wraps errors after which the command framing can no longer be
// trusted. The connection must be closed.
var ErrFatal = errors.New("fatal protocol error")

// SyntaxError is a recoverable error: the full command was consumed and the
// client can be answered with BAD.
type SyntaxError struct{ Msg string }

func (e *SyntaxError) Error() string { return e.Msg }

func syntaxErr(format string, args ...any) error {
	return &SyntaxError{Msg: fmt.Sprintf(format, args...)}
}

func fatal(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFatal, fmt.Sprintf(format, args...))
}

// Segment is one CRLF-terminated line of a command (without the CRLF), plus
// the literal that followed it, if the line ended with a literal marker.
type Segment struct {
	Text       []byte
	HasLiteral bool
	Literal    []byte
}

// RawCommand is a complete client command with all literals read.
type RawCommand struct {
	Segments []Segment
}

// ReadCommand reads one complete command. Before reading the data of a
// synchronizing literal, cont is called so the caller can send a "+"
// continuation to the client.
func ReadCommand(r *bufio.Reader, lim Limits, cont func() error) (*RawCommand, error) {
	var rc RawCommand
	var total int64
	for {
		line, err := readLine(r, lim.MaxLine)
		if err != nil {
			return nil, err
		}
		total += int64(len(line)) + 2
		if total > lim.MaxCommand {
			return nil, fatal("command too long")
		}
		seg := Segment{Text: line}
		n, nonSync, isLit, err := literalSpec(line)
		if err != nil {
			return nil, err
		}
		if !isLit {
			rc.Segments = append(rc.Segments, seg)
			return &rc, nil
		}
		if len(rc.Segments)+1 > lim.MaxLiterals {
			return nil, fatal("too many literals")
		}
		if n > lim.MaxLiteral || total+n > lim.MaxCommand {
			return nil, fatal("literal too large")
		}
		if !nonSync && cont != nil {
			if err := cont(); err != nil {
				return nil, err
			}
		}
		data := make([]byte, n)
		if _, err := readFull(r, data); err != nil {
			return nil, err
		}
		total += n
		seg.HasLiteral = true
		seg.Literal = data
		rc.Segments = append(rc.Segments, seg)
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// readLine reads one line terminated by CRLF and returns it without CRLF.
// Bare LF, bare CR and NUL are rejected as fatal: a peer that disagrees with
// us about line boundaries must not be allowed to continue.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > max+2 {
			return nil, fatal("line too long")
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
		return nil, fatal("line not terminated by CRLF")
	}
	line := buf[:len(buf)-2]
	if bytes.IndexByte(line, '\r') >= 0 || bytes.IndexByte(line, 0) >= 0 {
		return nil, fatal("CR or NUL inside line")
	}
	return line, nil
}

// literalSpec checks whether line ends in a literal marker "{N}" or "{N+}".
// N must be plain decimal digits; anything else ending in "}" that looks like
// a literal marker is fatal, because the peer may interpret it differently.
func literalSpec(line []byte) (n int64, nonSync, ok bool, err error) {
	if len(line) == 0 || line[len(line)-1] != '}' {
		return 0, false, false, nil
	}
	open := bytes.LastIndexByte(line, '{')
	if open < 0 {
		return 0, false, false, nil
	}
	inner := line[open+1 : len(line)-1]
	if len(inner) > 0 && inner[len(inner)-1] == '+' {
		nonSync = true
		inner = inner[:len(inner)-1]
	}
	if len(inner) == 0 || len(inner) > 10 {
		return 0, false, false, fatal("malformed literal marker")
	}
	for _, c := range inner {
		if c < '0' || c > '9' {
			return 0, false, false, fatal("malformed literal marker")
		}
	}
	v, perr := strconv.ParseInt(string(inner), 10, 64)
	if perr != nil {
		return 0, false, false, fatal("malformed literal marker")
	}
	return v, nonSync, true, nil
}

// ReadLine reads a single CRLF-terminated line (without CRLF), applying the
// same strictness as ReadCommand. It is used while the client is in IDLE.
func ReadLine(r *bufio.Reader, max int) ([]byte, error) {
	return readLine(r, max)
}
