// Package upstream manages the proxy's own IMAP connection to the real
// server. Only commands produced by package policy (plus LOGIN, CAPABILITY,
// STARTTLS, LOGOUT and DONE issued by this package) are ever written.
package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arj/imap-readonly-proxy/internal/imapwire"
)

// Security selects how the proxy connects to the upstream server.
type Security string

const (
	SecurityTLS      Security = "tls"
	SecurityStartTLS Security = "starttls"
	// SecurityInsecurePlaintext is only accepted for loopback hosts and
	// exists for local testing.
	SecurityInsecurePlaintext Security = "insecure-plaintext"
)

// Endpoint describes the upstream server.
type Endpoint struct {
	Host          string
	Port          int
	Security      Security
	TLSServerName string // defaults to Host
	CAFile        string // optional; defaults to the system roots
}

// Timeouts used for upstream I/O.
var (
	DialTimeout    = 15 * time.Second
	CommandTimeout = 5 * time.Minute
	IdleTimeout    = 31 * time.Minute
)

// Conn is an authenticated upstream connection.
type Conn struct {
	nc   net.Conn
	r    *bufio.Reader
	caps map[string]bool
	seq  int
	// pending holds a tagged response consumed while waiting for a
	// literal continuation.
	pending *Response
}

// Caps returns the upstream capabilities after login.
func (c *Conn) Caps() map[string]bool { return c.caps }

// Close closes the connection without LOGOUT.
func (c *Conn) Close() error { return c.nc.Close() }

// Reader exposes the buffered reader for response handling.
func (c *Conn) Reader() *bufio.Reader { return c.r }

// SetDeadline sets the read/write deadline of the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error { return c.nc.SetDeadline(t) }

// NextTag returns a fresh upstream tag. Client tags are never sent upstream.
func (c *Conn) NextTag() string {
	c.seq++
	return "P" + strconv.Itoa(c.seq)
}

func tlsConfig(ep Endpoint) (*tls.Config, error) {
	name := ep.TLSServerName
	if name == "" {
		name = ep.Host
	}
	cfg := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
	if ep.CAFile != "" {
		pem, err := os.ReadFile(ep.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Dial connects to the upstream server, establishes TLS as configured and
// logs in with the given credentials.
func Dial(ctx context.Context, ep Endpoint, user, pass string) (*Conn, error) {
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	d := net.Dialer{Timeout: DialTimeout}
	var nc net.Conn
	var err error

	switch ep.Security {
	case SecurityTLS:
		cfg, cerr := tlsConfig(ep)
		if cerr != nil {
			return nil, cerr
		}
		td := tls.Dialer{NetDialer: &d, Config: cfg}
		nc, err = td.DialContext(ctx, "tcp", addr)
	case SecurityStartTLS, SecurityInsecurePlaintext:
		nc, err = d.DialContext(ctx, "tcp", addr)
	default:
		return nil, fmt.Errorf("unknown upstream security %q", ep.Security)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	c := &Conn{nc: nc, r: bufio.NewReaderSize(nc, 64<<10)}
	_ = nc.SetDeadline(time.Now().Add(DialTimeout * 2))

	if err := c.readGreeting(); err != nil {
		nc.Close()
		return nil, err
	}
	if ep.Security == SecurityStartTLS {
		if err := c.startTLS(ep); err != nil {
			nc.Close()
			return nil, err
		}
	}
	if err := c.refreshCaps(); err != nil {
		nc.Close()
		return nil, err
	}
	if c.caps["LOGINDISABLED"] {
		nc.Close()
		return nil, errors.New("upstream advertises LOGINDISABLED")
	}
	if err := c.login(user, pass); err != nil {
		c.nc.Close()
		return nil, err
	}
	_ = c.nc.SetDeadline(time.Now().Add(DialTimeout * 2))
	// Capabilities may change after authentication.
	if err := c.refreshCaps(); err != nil {
		nc.Close()
		return nil, err
	}
	_ = c.nc.SetDeadline(time.Time{})
	return c, nil
}

func (c *Conn) readGreeting() error {
	line, err := readLine(c.r)
	if err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if !bytes.HasPrefix(line, []byte("* OK")) {
		// PREAUTH and BYE are both rejected: the proxy must authenticate
		// with the configured credentials.
		return fmt.Errorf("unexpected greeting %q", bytes.TrimSpace(line))
	}
	return nil
}

func (c *Conn) startTLS(ep Endpoint) error {
	tag := c.NextTag()
	if _, err := fmt.Fprintf(c.nc, "%s STARTTLS\r\n", tag); err != nil {
		return err
	}
	status, err := c.waitTagged(tag, nil)
	if err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if status != "OK" {
		return fmt.Errorf("starttls rejected by upstream")
	}
	// Anything already buffered was sent before the TLS handshake and is
	// not protected; refuse it (STARTTLS command injection, CVE-2011-0411
	// class).
	if c.r.Buffered() != 0 {
		return errors.New("starttls: unexpected plaintext data after OK")
	}
	cfg, err := tlsConfig(ep)
	if err != nil {
		return err
	}
	tc := tls.Client(c.nc, cfg)
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("starttls handshake: %w", err)
	}
	c.nc = tc
	c.r = bufio.NewReaderSize(tc, 64<<10)
	return nil
}

func (c *Conn) refreshCaps() error {
	tag := c.NextTag()
	if _, err := fmt.Fprintf(c.nc, "%s CAPABILITY\r\n", tag); err != nil {
		return err
	}
	caps := map[string]bool{}
	status, err := c.waitTagged(tag, func(line []byte) {
		if after, ok := bytes.CutPrefix(line, []byte("* CAPABILITY ")); ok {
			for _, f := range strings.Fields(string(after)) {
				caps[strings.ToUpper(f)] = true
			}
		}
	})
	if err != nil {
		return fmt.Errorf("capability: %w", err)
	}
	if status != "OK" {
		return errors.New("capability command failed")
	}
	c.caps = caps
	return nil
}

func (c *Conn) login(user, pass string) error {
	b := new(imapwire.Builder).Atom("LOGIN").SP().String([]byte(user)).SP().String([]byte(pass))
	resp, err := c.Execute(b.Parts(), func(r *Response) error { return r.Stream(c.r, discard{}) })
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if Status(resp.First) != "OK" {
		return errors.New("upstream login failed")
	}
	return nil
}

// waitTagged reads single-line responses until the tagged completion for
// tag and returns its status. It is used only during setup, where no
// literals are expected.
func (c *Conn) waitTagged(tag string, onUntagged func([]byte)) (string, error) {
	for {
		resp, err := ReadResponseStart(c.r)
		if err != nil {
			return "", err
		}
		if resp.HasMore {
			if err := resp.Stream(c.r, discard{}); err != nil {
				return "", err
			}
			continue
		}
		switch resp.Kind {
		case Untagged:
			if onUntagged != nil {
				onUntagged(resp.First)
			}
		case Continuation:
			return "", fmt.Errorf("%w: unexpected continuation", ErrProtocol)
		case Tagged:
			if resp.Tag != tag {
				return "", fmt.Errorf("%w: unexpected tag", ErrProtocol)
			}
			return Status(resp.First), nil
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Status extracts the status word (OK, NO, BAD) of a tagged response.
func Status(line []byte) string {
	f := bytes.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return strings.ToUpper(string(f[1]))
}

// UntaggedHandler handles untagged responses that arrive while a command
// is in progress.
type UntaggedHandler func(resp *Response) error

// send writes a command built from parts. Literals use LITERAL+ when the
// upstream supports it; otherwise the proxy waits for the continuation.
// If the upstream rejects the command before a continuation, the tagged
// response is left for the caller to read.
func (c *Conn) send(tag string, parts []imapwire.Part, onUntagged UntaggedHandler) error {
	var buf bytes.Buffer
	buf.WriteString(tag)
	buf.WriteByte(' ')
	literalPlus := c.caps["LITERAL+"]
	for _, p := range parts {
		if !p.IsLiteral {
			buf.Write(p.Text)
			continue
		}
		if literalPlus {
			fmt.Fprintf(&buf, "{%d+}\r\n", len(p.Literal))
			buf.Write(p.Literal)
			continue
		}
		fmt.Fprintf(&buf, "{%d}\r\n", len(p.Literal))
		if _, err := c.nc.Write(buf.Bytes()); err != nil {
			return err
		}
		buf.Reset()
		ok, err := c.waitContinuation(tag, onUntagged)
		if err != nil {
			return err
		}
		if !ok {
			// Rejected; do not send the literal or the rest.
			return errRejected
		}
		buf.Write(p.Literal)
	}
	_, err := c.nc.Write(buf.Bytes())
	return err
}

var errRejected = errors.New("rejected before continuation")

func (c *Conn) waitContinuation(tag string, onUntagged UntaggedHandler) (bool, error) {
	for {
		resp, err := ReadResponseStart(c.r)
		if err != nil {
			return false, err
		}
		switch resp.Kind {
		case Continuation:
			return true, nil
		case Untagged:
			if onUntagged == nil {
				if err := resp.Stream(c.r, discard{}); err != nil {
					return false, err
				}
				continue
			}
			if err := onUntagged(resp); err != nil {
				return false, err
			}
		case Tagged:
			if resp.Tag != tag {
				return false, fmt.Errorf("%w: unexpected tag", ErrProtocol)
			}
			c.pending = resp
			return false, nil
		}
	}
}

// Execute sends a command and processes responses until its tagged
// completion, which is returned. Untagged responses are passed to
// onUntagged, which must fully consume them (Stream or Buffer).
func (c *Conn) Execute(parts []imapwire.Part, onUntagged UntaggedHandler) (*Response, error) {
	tag := c.NextTag()
	_ = c.nc.SetDeadline(time.Now().Add(CommandTimeout))
	defer c.nc.SetDeadline(time.Time{})
	c.pending = nil
	if err := c.send(tag, parts, onUntagged); err != nil && !errors.Is(err, errRejected) {
		return nil, err
	}
	if c.pending != nil {
		resp := c.pending
		c.pending = nil
		return resp, nil
	}
	return c.ReadUntilTagged(tag, CommandTimeout, onUntagged)
}

// ReadUntilTagged reads responses until the tagged completion for tag. The
// read deadline is renewed for every response.
func (c *Conn) ReadUntilTagged(tag string, timeout time.Duration, onUntagged UntaggedHandler) (*Response, error) {
	for {
		_ = c.nc.SetReadDeadline(time.Now().Add(timeout))
		resp, err := ReadResponseStart(c.r)
		if err != nil {
			return nil, err
		}
		switch resp.Kind {
		case Tagged:
			if resp.Tag != tag {
				return nil, fmt.Errorf("%w: unexpected tag", ErrProtocol)
			}
			return resp, nil
		case Continuation:
			return nil, fmt.Errorf("%w: unexpected continuation", ErrProtocol)
		case Untagged:
			if err := onUntagged(resp); err != nil {
				return nil, err
			}
		}
	}
}

// StartIdle sends IDLE and waits for the continuation. It returns the
// tag, or the tagged response if the server refused IDLE.
func (c *Conn) StartIdle(onUntagged UntaggedHandler) (string, *Response, error) {
	tag := c.NextTag()
	_ = c.nc.SetDeadline(time.Now().Add(CommandTimeout))
	if _, err := fmt.Fprintf(c.nc, "%s IDLE\r\n", tag); err != nil {
		return "", nil, err
	}
	c.pending = nil
	ok, err := c.waitContinuation(tag, onUntagged)
	if err != nil {
		return "", nil, err
	}
	_ = c.nc.SetDeadline(time.Time{})
	if !ok {
		resp := c.pending
		c.pending = nil
		return tag, resp, nil
	}
	return tag, nil, nil
}

// SendDone ends IDLE. It may be called concurrently with a reader.
func (c *Conn) SendDone() error {
	_ = c.nc.SetWriteDeadline(time.Now().Add(CommandTimeout))
	_, err := io.WriteString(c.nc, "DONE\r\n")
	return err
}

// Logout sends LOGOUT and closes the connection.
func (c *Conn) Logout() {
	_ = c.nc.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.nc, "%s LOGOUT\r\n", c.NextTag())
	c.nc.Close()
}
