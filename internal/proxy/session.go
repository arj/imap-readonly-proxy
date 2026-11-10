package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/imapwire"
	"github.com/arj/imap-readonly-proxy/internal/policy"
	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

// Timeouts for the client side.
var (
	PreAuthTimeout    = 60 * time.Second
	AuthTimeout       = 30 * time.Minute // RFC 3501 autologout minimum
	ClientIdleTimeout = 30 * time.Minute
	WriteTimeout      = 10 * time.Minute
	LoginFailDelay    = time.Second
	MaxLoginFailures  = 3
)

// dummyHash equalizes timing for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)

// Dialer connects to the upstream server. Tests may replace it.
type Dialer func(ctx context.Context, ep upstream.Endpoint, user, pass string) (*upstream.Conn, error)

type session struct {
	srv    *Server
	nc     net.Conn
	ip     string
	r      *bufio.Reader
	w      *bufio.Writer
	log    *slog.Logger
	state  policy.State
	acct   *config.Account
	up     *upstream.Conn
	caps   policy.UpstreamCaps
	fails  int
	closed bool
}

const preAuthCaps = "IMAP4rev1 LITERAL+"

func (s *session) capString() string {
	c := preAuthCaps
	if s.state == policy.NotAuthenticated {
		return c
	}
	if s.caps.Idle {
		c += " IDLE"
	}
	if s.caps.Namespace {
		c += " NAMESPACE"
	}
	if s.caps.Unselect {
		c += " UNSELECT"
	}
	return c
}

func (s *session) run() {
	defer func() {
		if s.up != nil {
			s.up.Logout()
		}
		s.nc.Close()
	}()
	s.writef("* OK [CAPABILITY %s] imap-readonly-proxy ready\r\n", preAuthCaps)
	if s.flush() != nil {
		return
	}
	for !s.closed {
		timeout := AuthTimeout
		if s.state == policy.NotAuthenticated {
			timeout = PreAuthTimeout
		}
		_ = s.nc.SetReadDeadline(time.Now().Add(timeout))
		rc, err := imapwire.ReadCommand(s.r, imapwire.DefaultLimits, func() error {
			s.writef("+ Ready for literal data\r\n")
			return s.flush()
		})
		if err != nil {
			var se *imapwire.SyntaxError
			switch {
			case errors.As(err, &se):
				s.writef("* BAD %s\r\n", se.Msg)
				if s.flush() != nil {
					return
				}
				continue
			case errors.Is(err, imapwire.ErrFatal):
				s.log.Warn("closing connection", "reason", err.Error())
				s.writef("* BYE Protocol error\r\n")
				s.flush()
			case errors.Is(err, io.EOF):
			default:
				s.log.Debug("client read failed", "err", err)
			}
			return
		}
		_ = s.nc.SetWriteDeadline(time.Now().Add(WriteTimeout))
		if err := s.handle(rc); err != nil {
			s.log.Info("session ended", "reason", err.Error())
			return
		}
		if s.flush() != nil {
			return
		}
	}
}

func (s *session) writef(format string, args ...any) {
	fmt.Fprintf(s.w, format, args...)
}

func (s *session) flush() error { return s.w.Flush() }

func tagOf(rc *imapwire.RawCommand) string {
	if len(rc.Segments) == 0 {
		return "*"
	}
	t := rc.Segments[0].Text
	if i := bytes.IndexByte(t, ' '); i > 0 {
		t = t[:i]
	}
	if policy.ValidTag(t) {
		return string(t)
	}
	return "*"
}

func (s *session) handle(rc *imapwire.RawCommand) error {
	toks, err := imapwire.Tokenize(rc)
	if err != nil {
		s.writef("%s BAD %s\r\n", tagOf(rc), err.Error())
		return nil
	}
	req, rej := policy.Parse(toks, s.state, s.caps)
	if rej != nil {
		if rej.Kind == "NO" {
			s.log.Warn("refused command", "tag", rej.Tag, "reason", rej.Text)
		}
		s.writef("%s %s %s\r\n", rej.Tag, rej.Kind, rej.Text)
		return nil
	}
	switch req.Action {
	case policy.ActCapability:
		s.writef("* CAPABILITY %s\r\n%s OK CAPABILITY completed\r\n", s.capString(), req.Tag)
	case policy.ActLogout:
		s.writef("* BYE imap-readonly-proxy logging out\r\n%s OK LOGOUT completed\r\n", req.Tag)
		s.closed = true
	case policy.ActNoop:
		if s.state == policy.NotAuthenticated {
			s.writef("%s OK NOOP completed\r\n", req.Tag)
			return nil
		}
		return s.forward(req, nil)
	case policy.ActLogin:
		return s.login(req)
	case policy.ActExamine:
		if !s.acct.FolderVisible(req.Mailbox) {
			s.writef("%s NO [NONEXISTENT] Mailbox does not exist\r\n", req.Tag)
			return nil
		}
		return s.forward(req, func(status string) {
			if status == "OK" {
				s.state = policy.Selected
			} else {
				s.state = policy.Authenticated
			}
		})
	case policy.ActStatus:
		if !s.acct.FolderVisible(req.Mailbox) {
			s.writef("%s NO [NONEXISTENT] Mailbox does not exist\r\n", req.Tag)
			return nil
		}
		return s.forward(req, nil)
	case policy.ActClose:
		return s.forward(req, func(status string) {
			if status == "OK" {
				s.state = policy.Authenticated
			}
		})
	case policy.ActIdle:
		return s.idle(req)
	default:
		return s.forward(req, nil)
	}
	return nil
}

func (s *session) login(req *policy.Request) error {
	if !s.srv.limiter.LoginAllowed(s.ip) {
		time.Sleep(LoginFailDelay)
		s.writef("%s NO [UNAVAILABLE] Too many failed logins, try again later\r\n", req.Tag)
		return nil
	}
	acct := s.srv.cfg.Lookup(req.User)
	hash := dummyHash
	if acct != nil {
		hash = []byte(acct.LocalPasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(req.Pass)) != nil || acct == nil {
		s.srv.limiter.Failure(s.ip)
		s.fails++
		s.log.Warn("login failed")
		time.Sleep(LoginFailDelay)
		s.writef("%s NO [AUTHENTICATIONFAILED] Authentication failed\r\n", req.Tag)
		if s.fails >= MaxLoginFailures {
			s.writef("* BYE Too many failed logins\r\n")
			s.closed = true
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*upstream.DialTimeout)
	defer cancel()
	up, err := s.srv.dial(ctx, acct.Endpoint(), acct.RemoteUser, acct.RemotePassword)
	if err != nil {
		s.log.Error("upstream connection failed", "user", acct.LocalUser, "err", err)
		s.writef("%s NO [UNAVAILABLE] Upstream server unavailable\r\n", req.Tag)
		return nil
	}
	caps := up.Caps()
	s.up = up
	s.acct = acct
	s.caps = policy.UpstreamCaps{Idle: caps["IDLE"], Unselect: caps["UNSELECT"], Namespace: caps["NAMESPACE"]}
	s.state = policy.Authenticated
	s.log = s.log.With("user", acct.LocalUser)
	s.log.Info("login successful")
	s.writef("%s OK [CAPABILITY %s] Logged in (read-only)\r\n", req.Tag, s.capString())
	return nil
}

// forward executes a request upstream, relaying untagged responses and the
// rewritten tagged completion to the client.
func (s *session) forward(req *policy.Request, onDone func(status string)) error {
	resp, err := s.up.Execute(req.Upstream, s.relay)
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	status := upstream.Status(resp.First)
	if onDone != nil {
		onDone(status)
	}
	s.writeTagged(req.Tag, resp.First)
	return nil
}

// writeTagged rewrites the upstream tag to the client tag.
func (s *session) writeTagged(clientTag string, line []byte) {
	sp := bytes.IndexByte(line, ' ')
	rest := line[sp+1:] // "OK [code] text\r\n"
	textStart := bytes.IndexByte(rest, ' ') + 1
	if textStart > 0 {
		rest = stripCapabilityCode(rest, textStart)
	}
	s.w.WriteString(clientTag)
	s.w.WriteByte(' ')
	s.w.Write(rest)
}

// relay forwards one untagged response to the client.
func (s *session) relay(resp *upstream.Response) error {
	first := resp.First
	upper := bytes.ToUpper(first[:min(len(first), 16)])
	switch {
	case bytes.HasPrefix(upper, []byte("* CAPABILITY ")):
		// The client sees the proxy's capabilities, never the upstream's.
		return resp.Stream(s.up.Reader(), io.Discard)
	case s.acct.HasFolderFilter() && (bytes.HasPrefix(upper, []byte("* LIST ")) || bytes.HasPrefix(upper, []byte("* LSUB "))):
		full, err := resp.Buffer(s.up.Reader())
		if err != nil {
			return err
		}
		name, ok := parseListMailbox(full)
		if !ok || !s.acct.FolderVisible(name) {
			return nil // fail closed
		}
		_, err = s.w.Write(full)
		return err
	case bytes.HasPrefix(upper, []byte("* OK ")), bytes.HasPrefix(upper, []byte("* NO ")):
		first = stripCapabilityCode(first, 5)
	case bytes.HasPrefix(upper, []byte("* BAD ")):
		first = stripCapabilityCode(first, 6)
	}
	if _, err := s.w.Write(first); err != nil {
		return err
	}
	return resp.Stream(s.up.Reader(), s.w)
}

// stripCapabilityCode removes a "[CAPABILITY ...]" response code that starts
// at textStart, so clients never see upstream capabilities.
func stripCapabilityCode(line []byte, textStart int) []byte {
	if textStart >= len(line) {
		return line
	}
	text := line[textStart:]
	if !bytes.HasPrefix(bytes.ToUpper(text[:min(len(text), 12)]), []byte("[CAPABILITY ")) {
		return line
	}
	end := bytes.IndexByte(text, ']')
	if end < 0 {
		return line
	}
	out := append([]byte{}, line[:textStart]...)
	return append(out, bytes.TrimPrefix(text[end+1:], []byte(" "))...)
}

func (s *session) idle(req *policy.Request) error {
	tag, refused, err := s.up.StartIdle(s.relay)
	if err != nil {
		return fmt.Errorf("upstream idle: %w", err)
	}
	if refused != nil {
		s.writeTagged(req.Tag, refused.First)
		return nil
	}
	s.writef("+ idling\r\n")
	if err := s.flush(); err != nil {
		return err
	}

	type result struct {
		resp *upstream.Response
		err  error
	}
	done := make(chan result, 1)
	var clientDone atomic.Bool
	go func() {
		resp, err := s.up.ReadUntilTagged(tag, upstream.IdleTimeout, func(r *upstream.Response) error {
			if err := s.relay(r); err != nil {
				return err
			}
			_ = s.nc.SetWriteDeadline(time.Now().Add(WriteTimeout))
			return s.flush()
		})
		if !clientDone.Load() {
			// Upstream ended IDLE first: unblock the client reader.
			_ = s.nc.SetReadDeadline(time.Now())
		}
		done <- result{resp, err}
	}()

	_ = s.nc.SetReadDeadline(time.Now().Add(ClientIdleTimeout))
	line, rerr := imapwire.ReadLine(s.r, 64)
	if rerr != nil || !strings.EqualFold(string(line), "DONE") {
		// Anything other than DONE ends the session: no command is ever
		// forwarded while the upstream is idling.
		s.up.Close()
		<-done
		s.writef("* BYE Expected DONE\r\n")
		s.flush()
		return errors.New("IDLE ended without DONE")
	}
	clientDone.Store(true)
	if err := s.up.SendDone(); err != nil {
		return err
	}
	res := <-done
	if res.err != nil {
		return fmt.Errorf("upstream idle: %w", res.err)
	}
	s.writeTagged(req.Tag, res.resp.First)
	return nil
}

// parseListMailbox extracts the mailbox name from a full LIST/LSUB
// response: "* LIST (flags) delim mailbox". Returns ok=false on any
// unexpected syntax so the caller can fail closed.
func parseListMailbox(full []byte) (string, bool) {
	b := full[len("* LIST "):]
	if len(b) == 0 || b[0] != '(' {
		return "", false
	}
	end := bytes.IndexByte(b, ')')
	if end < 0 || end+1 >= len(b) || b[end+1] != ' ' {
		return "", false
	}
	b = b[end+2:]
	switch {
	case len(b) >= 4 && bytes.EqualFold(b[:3], []byte("NIL")) && b[3] == ' ':
		b = b[4:]
	case len(b) >= 4 && b[0] == '"' && b[1] != '\\' && b[2] == '"' && b[3] == ' ':
		b = b[4:]
	case len(b) >= 5 && b[0] == '"' && b[1] == '\\' && b[3] == '"' && b[4] == ' ':
		b = b[5:]
	default:
		return "", false
	}
	b = bytes.TrimSuffix(b, []byte("\r\n"))
	if len(b) == 0 {
		return "", false
	}
	switch b[0] {
	case '"':
		var out []byte
		for i := 1; i < len(b); i++ {
			switch b[i] {
			case '\\':
				if i+1 >= len(b) {
					return "", false
				}
				i++
				out = append(out, b[i])
			case '"':
				if i != len(b)-1 {
					return "", false
				}
				return string(out), true
			default:
				out = append(out, b[i])
			}
		}
		return "", false
	case '{':
		crlf := bytes.Index(b, []byte("}\r\n"))
		if crlf < 0 {
			return "", false
		}
		var n int
		if _, err := fmt.Sscanf(string(b[1:crlf]), "%d", &n); err != nil || n < 0 {
			return "", false
		}
		data := b[crlf+3:]
		if len(data) != n {
			return "", false
		}
		return string(data), true
	default:
		if bytes.ContainsAny(b, " ()\"{") {
			return "", false
		}
		return string(b), true
	}
}
