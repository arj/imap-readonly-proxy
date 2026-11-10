// Package restapi implements the read-only HTTPS REST API.
//
// See docs/adr/0002-rest-api.md. Each request opens its own upstream
// connection, issues read-only IMAP commands through package policy and
// closes the connection again.
package restapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/ratelimit"
	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

// Dialer connects to the upstream server.
type Dialer func(ctx context.Context, ep upstream.Endpoint, user, pass string) (*upstream.Conn, error)

// Timeouts for the HTTP side.
var (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 10 * time.Minute
	IdleTimeout       = 2 * time.Minute
	UpstreamTimeout   = 30 * time.Second
)

// API serves the REST endpoints.
type API struct {
	cfg     *config.Config
	log     *slog.Logger
	dial    Dialer
	limiter *ratelimit.Limiter
	tokens  []tokenEntry
	mux     *http.ServeMux
	srv     *http.Server
}

type tokenEntry struct {
	hash [sha256.Size]byte
	acct *config.Account
}

// New creates the API. dial may be nil to use upstream.Dial.
func New(cfg *config.Config, log *slog.Logger, dial Dialer) *API {
	if dial == nil {
		dial = upstream.Dial
	}
	a := &API{
		cfg:     cfg,
		log:     log,
		dial:    dial,
		limiter: ratelimit.New(cfg.HTTP.MaxConcurrentRequests, cfg.HTTP.MaxConcurrentRequestsPerIP, 10, 15*time.Minute),
		mux:     http.NewServeMux(),
	}
	for i := range cfg.Accounts {
		acct := &cfg.Accounts[i]
		if acct.APITokenSHA256 == "" {
			continue
		}
		b, err := hex.DecodeString(acct.APITokenSHA256)
		if err != nil || len(b) != sha256.Size {
			continue // rejected by config validation
		}
		var e tokenEntry
		copy(e.hash[:], b)
		e.acct = acct
		a.tokens = append(a.tokens, e)
	}
	a.routes()
	return a
}

// Handler returns the HTTP handler (for tests).
func (a *API) Handler() http.Handler { return a.middleware(a.mux) }

// Listen opens the configured listener (TLS unless insecure_plaintext).
func (a *API) Listen() (net.Listener, error) {
	hc := a.cfg.HTTP
	ln, err := net.Listen("tcp", hc.Listen)
	if err != nil {
		return nil, err
	}
	if hc.InsecurePlaintext {
		return ln, nil
	}
	cert, err := tls.LoadX509KeyPair(hc.TLSCert, hc.TLSKey)
	if err != nil {
		ln.Close()
		return nil, err
	}
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}), nil
}

// Serve serves HTTP requests until Close is called.
func (a *API) Serve(ln net.Listener) error {
	a.srv = &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(slogWriter{a.log}, "", 0),
	}
	err := a.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close shuts the server down, waiting briefly for running requests.
func (a *API) Close() error {
	if a.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.srv.Shutdown(ctx)
}

type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.l.Debug("http server", "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}

type ctxKey struct{}

// middleware sets security headers, authenticates and limits requests.
func (a *API) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
		h.Set("Referrer-Policy", "no-referrer")
		if !a.cfg.HTTP.InsecurePlaintext {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !a.limiter.LoginAllowed(ip) {
			writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		acct := a.authenticate(r)
		if acct == nil {
			a.limiter.Failure(ip)
			a.log.Warn("rest authentication failed", "client", ip)
			h.Set("WWW-Authenticate", `Bearer realm="imap-readonly-proxy"`)
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !a.limiter.Acquire(ip) {
			writeError(w, http.StatusTooManyRequests, "too many concurrent requests")
			return
		}
		defer a.limiter.Release(ip)

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, acct)))
		a.log.Info("rest request", "client", ip, "user", acct.LocalUser, "method", r.Method,
			"path", r.URL.EscapedPath(), "status", sw.status, "duration", time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// authenticate checks the bearer token in constant time against all
// configured tokens.
func (a *API) authenticate(r *http.Request) *config.Account {
	auth := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > 512 {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	var found *config.Account
	for _, e := range a.tokens {
		if subtle.ConstantTimeCompare(sum[:], e.hash[:]) == 1 {
			found = e.acct
		}
	}
	return found
}

func accountFrom(r *http.Request) *config.Account {
	acct, _ := r.Context().Value(ctxKey{}).(*config.Account)
	return acct
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// connect opens an authenticated upstream connection for the request. The
// connection is closed when the request context ends.
func (a *API) connect(r *http.Request, acct *config.Account) (*gateway, func(), error) {
	ctx, cancel := context.WithTimeout(r.Context(), UpstreamTimeout)
	defer cancel()
	up, err := a.dial(ctx, acct.Endpoint(), acct.RemoteUser, acct.RemotePassword)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(r.Context(), func() { up.Close() })
	done := func() {
		stop()
		up.Logout() // also closes the connection
	}
	return newGateway(up, acct), done, nil
}
