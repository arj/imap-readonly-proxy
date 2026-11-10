package restapi

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arj/imap-readonly-proxy/internal/imapwire"
	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

const (
	defaultLimit = 50
	maxLimit     = 200
	// maxSmallResponse bounds untagged responses other than message bodies.
	maxSmallResponse = 2 << 20
)

func (a *API) routes() {
	a.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	a.mux.HandleFunc("GET /api/v1/mailboxes", a.withConn(a.listMailboxes))
	a.mux.HandleFunc("GET /api/v1/mailboxes/{mailbox}", a.withConn(a.mailboxStatus))
	a.mux.HandleFunc("GET /api/v1/mailboxes/{mailbox}/messages", a.withConn(a.listMessages))
	a.mux.HandleFunc("GET /api/v1/mailboxes/{mailbox}/messages/{uid}", a.withConn(a.getMessage))
	a.mux.HandleFunc("GET /api/v1/mailboxes/{mailbox}/messages/{uid}/raw", a.withConn(a.getRaw))
	a.mux.HandleFunc("GET /api/v1/mailboxes/{mailbox}/messages/{uid}/attachments/{index}", a.withConn(a.getAttachment))
	a.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// The API is read-only: no method other than GET exists.
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "method not allowed (read-only API)")
			return
		}
		writeError(w, http.StatusNotFound, "not found")
	})
}

// httpError carries a status code to the client.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &httpError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, g *gateway) error

// withConn opens the upstream connection and maps errors to responses.
func (a *API) withConn(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		acct := accountFrom(r)
		if acct == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Validate the request before contacting the upstream.
		if err := validatePath(r); err != nil {
			a.respondError(w, err)
			return
		}
		g, done, err := a.connect(r, acct)
		if err != nil {
			a.log.Error("upstream connection failed", "user", acct.LocalUser, "err", err)
			writeError(w, http.StatusBadGateway, "upstream server unavailable")
			return
		}
		defer done()
		if err := h(w, r, g); err != nil {
			a.respondError(w, err)
		}
	}
}

func (a *API) respondError(w http.ResponseWriter, err error) {
	var he *httpError
	var rej *errRejected
	switch {
	case errors.As(err, &he):
		writeError(w, he.status, he.msg)
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.As(err, &rej):
		writeError(w, http.StatusBadRequest, "request not supported: "+rej.text)
	case errors.Is(err, upstream.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "upstream response too large")
	default:
		a.log.Error("rest request failed", "err", err)
		writeError(w, http.StatusBadGateway, "upstream error")
	}
}

func validatePath(r *http.Request) error {
	if m := r.PathValue("mailbox"); m != "" || strings.Contains(r.Pattern, "{mailbox}") {
		if _, err := mailboxParam(r); err != nil {
			return err
		}
	}
	if strings.Contains(r.Pattern, "{uid}") {
		if _, err := uidParam(r); err != nil {
			return err
		}
	}
	return nil
}

// mailboxParam returns the IMAP (modified UTF-7) name of the mailbox in
// the path. The path carries the UTF-8 name, percent-encoded.
func mailboxParam(r *http.Request) (string, error) {
	name := r.PathValue("mailbox")
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return "", badRequest("invalid mailbox name")
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return "", badRequest("invalid mailbox name")
		}
	}
	return encodeMailbox(name), nil
}

func uidParam(r *http.Request) (uint32, error) {
	s := r.PathValue("uid")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 || s[0] == '0' {
		return 0, badRequest("invalid uid")
	}
	return uint32(n), nil
}

// Mailbox is an entry of the mailbox list.
type Mailbox struct {
	Name      string   `json:"name"` // UTF-8; use (percent-encoded) in URLs
	Delimiter string   `json:"delimiter,omitempty"`
	Flags     []string `json:"flags"`
}

func (a *API) listMailboxes(w http.ResponseWriter, r *http.Request, g *gateway) error {
	var out []Mailbox
	b := new(imapwire.Builder).Atom("LIST").SP().String(nil).SP().String([]byte("*"))
	status, err := g.run(b, maxSmallResponse, func(data []byte) error {
		v, err := parseResponse(data)
		if err != nil || len(v) != 4 || !v[0].atomIs("LIST") || v[1].kind != kindList {
			return nil // fail closed: skip what cannot be parsed
		}
		raw := v[3].str()
		if v[3].kind == kindNil || !g.acct.FolderVisible(raw) {
			return nil
		}
		name, err := decodeMailbox(raw)
		if err != nil {
			return nil
		}
		mb := Mailbox{Name: name, Delimiter: v[2].str(), Flags: []string{}}
		for _, f := range v[1].list {
			mb.Flags = append(mb.Flags, f.str())
		}
		out = append(out, mb)
		return nil
	})
	if err != nil {
		return err
	}
	if status != "OK" {
		return errors.New("LIST failed")
	}
	if out == nil {
		out = []Mailbox{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": out})
	return nil
}

func (a *API) mailboxStatus(w http.ResponseWriter, r *http.Request, g *gateway) error {
	mbox, _ := mailboxParam(r)
	res := map[string]any{"name": r.PathValue("mailbox")}
	b := new(imapwire.Builder).Atom("STATUS").SP().String([]byte(mbox)).SP().Atom("(MESSAGES UNSEEN UIDNEXT UIDVALIDITY)")
	status, err := g.run(b, maxSmallResponse, func(data []byte) error {
		v, err := parseResponse(data)
		if err != nil || len(v) != 3 || !v[0].atomIs("STATUS") || v[2].kind != kindList {
			return nil
		}
		l := v[2].list
		for i := 0; i+1 < len(l); i += 2 {
			if n, ok := l[i+1].number(); ok {
				res[strings.ToLower(l[i].str())] = n
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if status != "OK" {
		return errNotFound
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

var uidValidityRe = regexp.MustCompile(`(?i)^\* OK \[UIDVALIDITY (\d+)\]`)

// examine opens the mailbox read-only and returns its UIDVALIDITY.
func (g *gateway) examine(mbox string) (uint64, error) {
	var uidValidity uint64
	b := new(imapwire.Builder).Atom("EXAMINE").SP().String([]byte(mbox))
	status, err := g.run(b, maxSmallResponse, func(data []byte) error {
		if m := uidValidityRe.FindSubmatch(data); m != nil {
			uidValidity, _ = strconv.ParseUint(string(m[1]), 10, 32)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if status != "OK" {
		return 0, errNotFound
	}
	return uidValidity, nil
}

// searchKeys translates query parameters into IMAP search keys.
func searchKeys(r *http.Request) (*imapwire.Builder, bool, error) {
	q := r.URL.Query()
	keys := new(imapwire.Builder)
	n := 0
	utf8Needed := false
	add := func() {
		if n > 0 {
			keys.SP()
		}
		n++
	}
	for param, vals := range q {
		if len(vals) != 1 {
			return nil, false, badRequest("parameter %q given more than once", param)
		}
	}
	strParams := []struct{ param, key string }{
		{"from", "FROM"}, {"to", "TO"}, {"cc", "CC"}, {"subject", "SUBJECT"},
		{"body", "BODY"}, {"text", "TEXT"},
	}
	known := map[string]bool{"limit": true, "before_uid": true}
	for _, sp := range strParams {
		known[sp.param] = true
		v := q.Get(sp.param)
		if !q.Has(sp.param) {
			continue
		}
		if v == "" || len(v) > 1000 || !utf8.ValidString(v) {
			return nil, false, badRequest("invalid %s", sp.param)
		}
		for _, c := range v {
			if c < 0x20 || c == 0x7f {
				return nil, false, badRequest("invalid %s", sp.param)
			}
			if c > 0x7e {
				utf8Needed = true
			}
		}
		add()
		keys.Atom(sp.key).SP().String([]byte(v))
	}
	for _, dp := range []struct{ param, key string }{{"since", "SINCE"}, {"before", "BEFORE"}, {"on", "ON"}} {
		known[dp.param] = true
		if !q.Has(dp.param) {
			continue
		}
		t, err := time.Parse("2006-01-02", q.Get(dp.param))
		if err != nil {
			return nil, false, badRequest("%s must be YYYY-MM-DD", dp.param)
		}
		add()
		keys.Atom(dp.key).SP().Atom(t.Format("2-Jan-2006"))
	}
	for _, fp := range []struct{ param, yes, no string }{{"unseen", "UNSEEN", "SEEN"}, {"flagged", "FLAGGED", "UNFLAGGED"}} {
		known[fp.param] = true
		if !q.Has(fp.param) {
			continue
		}
		v, err := strconv.ParseBool(q.Get(fp.param))
		if err != nil {
			return nil, false, badRequest("%s must be true or false", fp.param)
		}
		add()
		if v {
			keys.Atom(fp.yes)
		} else {
			keys.Atom(fp.no)
		}
	}
	for param := range q {
		if !known[param] {
			return nil, false, badRequest("unknown parameter %q", param)
		}
	}
	if n == 0 {
		keys.Atom("ALL")
	}
	return keys, utf8Needed, nil
}

// MessageSummary is an entry of the message list.
type MessageSummary struct {
	UID          uint32   `json:"uid"`
	Flags        []string `json:"flags"`
	InternalDate string   `json:"internal_date,omitempty"`
	Size         uint64   `json:"size"`
	Envelope
}

type fetchItem struct {
	uid          uint32
	flags        []string
	internalDate string
	size         uint64
	header       []byte
	body         []byte
	hasBody      bool
}

// parseFetch parses "* n FETCH (...)".
func parseFetch(data []byte) (*fetchItem, bool) {
	v, err := parseResponse(data)
	if err != nil || len(v) != 3 || !v[1].atomIs("FETCH") || v[2].kind != kindList {
		return nil, false
	}
	it := &fetchItem{}
	l := v[2].list
	for i := 0; i+1 < len(l); i += 2 {
		key := strings.ToUpper(l[i].str())
		val := l[i+1]
		switch {
		case key == "UID":
			n, ok := val.number()
			if !ok || n == 0 || n > 0xffffffff {
				return nil, false
			}
			it.uid = uint32(n)
		case key == "FLAGS":
			it.flags = []string{}
			for _, f := range val.list {
				it.flags = append(it.flags, f.str())
			}
		case key == "INTERNALDATE":
			if t, err := time.Parse("_2-Jan-2006 15:04:05 -0700", val.str()); err == nil {
				it.internalDate = t.Format(time.RFC3339)
			}
		case key == "RFC822.SIZE":
			it.size, _ = val.number()
		case strings.HasPrefix(key, "BODY[HEADER.FIELDS"):
			it.header = val.bytes
		case key == "BODY[]":
			it.body, it.hasBody = val.bytes, true
		}
	}
	return it, it.uid != 0
}

func (a *API) listMessages(w http.ResponseWriter, r *http.Request, g *gateway) error {
	mbox, _ := mailboxParam(r)
	keys, utf8Needed, err := searchKeys(r)
	if err != nil {
		return err
	}
	limit := defaultLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		if limit, err = strconv.Atoi(s); err != nil || limit < 1 || limit > maxLimit {
			return badRequest("limit must be 1..%d", maxLimit)
		}
	}
	var beforeUID uint64
	if s := r.URL.Query().Get("before_uid"); s != "" {
		if beforeUID, err = strconv.ParseUint(s, 10, 32); err != nil || beforeUID == 0 {
			return badRequest("invalid before_uid")
		}
	}

	uidValidity, err := g.examine(mbox)
	if err != nil {
		return err
	}
	resp := map[string]any{"mailbox": r.PathValue("mailbox"), "uidvalidity": uidValidity}
	if beforeUID == 1 {
		resp["total"], resp["messages"], resp["next_before_uid"] = 0, []MessageSummary{}, nil
		writeJSON(w, http.StatusOK, resp)
		return nil
	}

	b := searchCommand(keys, utf8Needed, beforeUID)

	var uids []uint32
	status, err := g.run(b, maxSmallResponse, func(data []byte) error {
		v, err := parseResponse(data)
		if err != nil || len(v) == 0 || !v[0].atomIs("SEARCH") {
			return nil
		}
		for _, x := range v[1:] {
			if n, ok := x.number(); ok && n > 0 && n <= 0xffffffff {
				uids = append(uids, uint32(n))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if status != "OK" {
		return badRequest("search rejected by server")
	}
	slices.Sort(uids)
	uids = slices.Compact(uids)
	total := len(uids)
	page := uids
	if len(page) > limit {
		page = page[len(page)-limit:]
	}
	slices.Reverse(page) // newest (highest UID) first

	summaries := []MessageSummary{}
	if len(page) > 0 {
		fb := summaryFetchCommand(page)
		byUID := map[uint32]*fetchItem{}
		status, err := g.run(fb, maxSmallResponse, func(data []byte) error {
			if it, ok := parseFetch(data); ok {
				if prev := byUID[it.uid]; prev != nil {
					// Merge unsolicited partial FETCH responses.
					if it.header == nil {
						it.header = prev.header
					}
					if it.flags == nil {
						it.flags = prev.flags
					}
				}
				byUID[it.uid] = it
			}
			return nil
		})
		if err != nil {
			return err
		}
		if status != "OK" {
			return errors.New("FETCH failed")
		}
		for _, u := range page {
			it := byUID[u]
			if it == nil {
				continue // expunged meanwhile
			}
			if it.flags == nil {
				it.flags = []string{}
			}
			summaries = append(summaries, MessageSummary{
				UID: u, Flags: it.flags, InternalDate: it.internalDate, Size: it.size,
				Envelope: envelopeFrom(parseHeaderBlock(it.header)),
			})
		}
	}
	resp["total"] = total
	resp["messages"] = summaries
	if total > len(page) && len(page) > 0 {
		resp["next_before_uid"] = page[len(page)-1]
	} else {
		resp["next_before_uid"] = nil
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// searchCommand builds the UID SEARCH command for a message list.
func searchCommand(keys *imapwire.Builder, utf8Needed bool, beforeUID uint64) *imapwire.Builder {
	b := new(imapwire.Builder).Atom("UID SEARCH")
	if utf8Needed {
		b.SP().Atom("CHARSET UTF-8")
	}
	b.SP()
	if beforeUID > 1 {
		b.Atom("UID 1:").Number(beforeUID - 1).SP()
	}
	b.Atom("(")
	appendParts(b, keys)
	b.Atom(")")
	return b
}

// summaryFetchCommand builds the FETCH command for a message list page.
func summaryFetchCommand(uids []uint32) *imapwire.Builder {
	set := make([]string, len(uids))
	for i, u := range uids {
		set[i] = strconv.FormatUint(uint64(u), 10)
	}
	return new(imapwire.Builder).Atom("UID FETCH " + strings.Join(set, ",") +
		" (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (" + strings.Join(envelopeHeaderFields, " ") + ")])")
}

// appendParts appends the contents of src to dst.
func appendParts(dst, src *imapwire.Builder) {
	parts := src.Parts()
	for i, p := range parts {
		if p.IsLiteral {
			dst.Literal(p.Literal)
			continue
		}
		t := p.Text
		if i == len(parts)-1 {
			t = t[:len(t)-2] // strip CRLF added by Parts
		}
		dst.Atom(string(t))
	}
}

// fetchMessage returns metadata and the full raw message.
func (a *API) fetchMessage(r *http.Request, g *gateway) (*fetchItem, error) {
	mbox, _ := mailboxParam(r)
	uid, _ := uidParam(r)
	if _, err := g.examine(mbox); err != nil {
		return nil, err
	}
	var meta *fetchItem
	mb := new(imapwire.Builder).Atom("UID FETCH ").Number(uint64(uid)).Atom(" (UID FLAGS INTERNALDATE RFC822.SIZE)")
	status, err := g.run(mb, maxSmallResponse, func(data []byte) error {
		if it, ok := parseFetch(data); ok && it.uid == uid {
			meta = it
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if status != "OK" || meta == nil {
		return nil, errNotFound
	}
	max := a.cfg.HTTP.MaxMessageBytes
	if int64(meta.size) > max {
		return nil, &httpError{http.StatusRequestEntityTooLarge, fmt.Sprintf("message is larger than max_message_bytes (%d)", max)}
	}
	bb := new(imapwire.Builder).Atom("UID FETCH ").Number(uint64(uid)).Atom(" (UID BODY.PEEK[])")
	status, err = g.run(bb, max+64<<10, func(data []byte) error {
		if it, ok := parseFetch(data); ok && it.uid == uid && it.hasBody {
			meta.body, meta.hasBody = it.body, true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if status != "OK" || !meta.hasBody {
		return nil, errNotFound
	}
	return meta, nil
}

// MessageDetail is the decoded message.
type MessageDetail struct {
	UID          uint32   `json:"uid"`
	Flags        []string `json:"flags"`
	InternalDate string   `json:"internal_date,omitempty"`
	Size         uint64   `json:"size"`
	Envelope
	Text        string       `json:"text"`
	HTML        string       `json:"html"`
	Attachments []Attachment `json:"attachments"`
}

func (a *API) getMessage(w http.ResponseWriter, r *http.Request, g *gateway) error {
	it, err := a.fetchMessage(r, g)
	if err != nil {
		return err
	}
	p, err := parseMessage(it.body)
	if err != nil {
		return &httpError{http.StatusUnprocessableEntity, "message cannot be parsed; use /raw"}
	}
	if it.flags == nil {
		it.flags = []string{}
	}
	if p.Attachments == nil {
		p.Attachments = []Attachment{}
	}
	writeJSON(w, http.StatusOK, MessageDetail{
		UID: it.uid, Flags: it.flags, InternalDate: it.internalDate, Size: it.size,
		Envelope: p.Envelope, Text: p.Text, HTML: p.HTML, Attachments: p.Attachments,
	})
	return nil
}

func (a *API) getRaw(w http.ResponseWriter, r *http.Request, g *gateway) error {
	it, err := a.fetchMessage(r, g)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%d.eml"`, it.uid))
	w.Header().Set("Content-Length", strconv.Itoa(len(it.body)))
	_, _ = w.Write(it.body)
	return nil
}

func (a *API) getAttachment(w http.ResponseWriter, r *http.Request, g *gateway) error {
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || idx < 0 || idx > maxMIMEParts {
		return badRequest("invalid attachment index")
	}
	it, err := a.fetchMessage(r, g)
	if err != nil {
		return err
	}
	p, err := parseMessage(it.body)
	if err != nil {
		return &httpError{http.StatusUnprocessableEntity, "message cannot be parsed; use /raw"}
	}
	if idx >= len(p.Attachments) {
		return errNotFound
	}
	att := p.Attachments[idx]
	// Always serve as a download: never let a browser render the content.
	w.Header().Set("Content-Type", "application/octet-stream")
	name := att.Filename
	if name == "" {
		name = fmt.Sprintf("attachment-%d", idx)
	}
	disp := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	if disp == "" {
		disp = fmt.Sprintf(`attachment; filename="attachment-%d"`, idx)
	}
	w.Header().Set("Content-Disposition", disp)
	w.Header().Set("X-Original-Content-Type", att.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(p.data[idx])))
	_, _ = w.Write(p.data[idx])
	return nil
}
