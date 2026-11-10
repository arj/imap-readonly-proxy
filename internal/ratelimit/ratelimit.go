// Package ratelimit provides connection limits and login-failure throttling.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter tracks concurrent connections and failed logins per client IP.
type Limiter struct {
	mu       sync.Mutex
	maxTotal int
	maxPerIP int
	total    int
	conns    map[string]int
	fails    map[string]*failures
	window   time.Duration
	maxFails int
	now      func() time.Time
}

type failures struct {
	count int
	start time.Time
}

// New returns a limiter. A client IP is locked out of logins after maxFails
// failures within window.
func New(maxTotal, maxPerIP, maxFails int, window time.Duration) *Limiter {
	return &Limiter{
		maxTotal: maxTotal, maxPerIP: maxPerIP, maxFails: maxFails, window: window,
		conns: map[string]int{}, fails: map[string]*failures{}, now: time.Now,
	}
}

// Acquire reserves a connection slot for ip.
func (l *Limiter) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.conns[ip] >= l.maxPerIP {
		return false
	}
	l.total++
	l.conns[ip]++
	return true
}

// Release frees a slot reserved with Acquire.
func (l *Limiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.conns[ip]--; l.conns[ip] <= 0 {
		delete(l.conns, ip)
	}
}

// LoginAllowed reports whether ip may attempt a login.
func (l *Limiter) LoginAllowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	if f == nil {
		return true
	}
	if l.now().Sub(f.start) > l.window {
		delete(l.fails, ip)
		return true
	}
	return f.count < l.maxFails
}

// Failure records a failed login for ip.
func (l *Limiter) Failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	f := l.fails[ip]
	if f == nil || now.Sub(f.start) > l.window {
		f = &failures{start: now}
		l.fails[ip] = f
	}
	f.count++
	// Bound memory: drop expired entries opportunistically.
	if len(l.fails) > 10000 {
		for k, v := range l.fails {
			if now.Sub(v.start) > l.window {
				delete(l.fails, k)
			}
		}
	}
}
