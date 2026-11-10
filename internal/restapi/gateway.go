package restapi

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/imapwire"
	"github.com/arj/imap-readonly-proxy/internal/policy"
	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

// gateway runs REST requests as IMAP commands.
//
// Every command is built in client syntax, rendered to wire bytes and then
// passed through exactly the same reader, tokenizer and policy as commands
// from IMAP clients. Only the policy's canonical re-encoding is sent
// upstream. The REST layer therefore cannot send anything an IMAP client
// could not, and it inherits the read-only guarantees (EXAMINE instead of
// SELECT, BODY.PEEK, no write commands).
type gateway struct {
	up    *upstream.Conn
	acct  *config.Account
	caps  policy.UpstreamCaps
	state policy.State
}

// errNotFound is returned for hidden or nonexistent mailboxes and messages.
var errNotFound = errors.New("not found")

// errRejected is returned when the policy refuses a generated command;
// this indicates invalid user input (for example, an unsupported value).
type errRejected struct{ text string }

func (e *errRejected) Error() string { return "rejected by policy: " + e.text }

// restActions are the policy actions the REST layer may use.
var restActions = map[policy.Action]bool{
	policy.ActExamine: true, policy.ActStatus: true, policy.ActList: true,
	policy.ActFetch: true, policy.ActSearch: true,
}

func newGateway(up *upstream.Conn, acct *config.Account) *gateway {
	c := up.Caps()
	return &gateway{
		up:    up,
		acct:  acct,
		caps:  policy.UpstreamCaps{Idle: c["IDLE"], Unselect: c["UNSELECT"], Namespace: c["NAMESPACE"]},
		state: policy.Authenticated,
	}
}

// renderClient renders parts the way an IMAP client using LITERAL+ would.
func renderClient(tag string, parts []imapwire.Part) []byte {
	var b bytes.Buffer
	b.WriteString(tag)
	b.WriteByte(' ')
	for _, p := range parts {
		if p.IsLiteral {
			b.WriteString("{" + strconv.Itoa(len(p.Literal)) + "+}\r\n")
			b.Write(p.Literal)
			continue
		}
		b.Write(p.Text)
	}
	return b.Bytes()
}

// run validates the command built by b and executes it upstream. Each
// untagged response is passed to onUntagged fully buffered (bounded by
// maxResp). It returns the upstream status (OK, NO, BAD).
func (g *gateway) run(b *imapwire.Builder, maxResp int64, onUntagged func(data []byte) error) (string, error) {
	req, err := g.prepare(b)
	if err != nil {
		return "", err
	}
	resp, err := g.up.Execute(req.Upstream, func(r *upstream.Response) error {
		data, err := r.BufferMax(g.up.Reader(), maxResp)
		if err != nil {
			return err
		}
		if onUntagged == nil {
			return nil
		}
		return onUntagged(data)
	})
	if err != nil {
		return "", err
	}
	status := upstream.Status(resp.First)
	if req.Action == policy.ActExamine {
		if status == "OK" {
			g.state = policy.Selected
		} else {
			g.state = policy.Authenticated
		}
	}
	return status, nil
}

// prepare validates a generated command exactly like an IMAP client
// command and returns the policy's request.
func (g *gateway) prepare(b *imapwire.Builder) (*policy.Request, error) {
	wire := renderClient("R", b.Parts())
	rc, err := imapwire.ReadCommand(bufio.NewReader(bytes.NewReader(wire)), imapwire.DefaultLimits, nil)
	if err != nil {
		return nil, &errRejected{err.Error()}
	}
	toks, err := imapwire.Tokenize(rc)
	if err != nil {
		return nil, &errRejected{err.Error()}
	}
	req, rej := policy.Parse(toks, g.state, g.caps)
	if rej != nil {
		return nil, &errRejected{rej.Text}
	}
	if !restActions[req.Action] || req.Upstream == nil {
		return nil, fmt.Errorf("internal error: action %v not allowed for REST", req.Action)
	}
	if (req.Action == policy.ActExamine || req.Action == policy.ActStatus) && !g.acct.FolderVisible(req.Mailbox) {
		return nil, errNotFound
	}
	return req, nil
}
