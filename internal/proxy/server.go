// Package proxy implements the client-facing IMAP server.
package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/ratelimit"
	"github.com/arj/imap-readonly-proxy/internal/upstream"
)

// Server accepts client connections.
type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	limiter *ratelimit.Limiter
	dial    Dialer

	mu sync.Mutex
	ln net.Listener
	wg sync.WaitGroup
}

// New creates a server. dial may be nil to use upstream.Dial.
func New(cfg *config.Config, log *slog.Logger, dial Dialer) *Server {
	if dial == nil {
		dial = upstream.Dial
	}
	return &Server{
		cfg:     cfg,
		log:     log,
		limiter: ratelimit.New(cfg.Server.MaxConnections, cfg.Server.MaxConnectionsPerIP, 10, 15*time.Minute),
		dial:    dial,
	}
}

// Listen opens the configured listener (TLS unless insecure_plaintext).
func (s *Server) Listen() (net.Listener, error) {
	sc := s.cfg.Server
	if sc.InsecurePlaintext {
		return net.Listen("tcp", sc.Listen)
	}
	cert, err := tls.LoadX509KeyPair(sc.TLSCert, sc.TLSKey)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", sc.Listen, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		ip, _, _ := net.SplitHostPort(nc.RemoteAddr().String())
		if !s.limiter.Acquire(ip) {
			_ = nc.SetWriteDeadline(time.Now().Add(time.Second))
			nc.Write([]byte("* BYE Too many connections\r\n"))
			nc.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.limiter.Release(ip)
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("session panic", "panic", r)
					nc.Close()
				}
			}()
			if tc, ok := nc.(*tls.Conn); ok {
				_ = tc.SetDeadline(time.Now().Add(PreAuthTimeout))
				if err := tc.Handshake(); err != nil {
					s.log.Debug("tls handshake failed", "client", ip, "err", err)
					tc.Close()
					return
				}
			}
			sess := &session{
				srv: s,
				nc:  nc,
				ip:  ip,
				r:   bufio.NewReaderSize(nc, 16<<10),
				w:   bufio.NewWriterSize(nc, 64<<10),
				log: s.log.With("client", ip),
			}
			sess.run()
		}()
	}
}

// Close stops accepting connections.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Close()
}
