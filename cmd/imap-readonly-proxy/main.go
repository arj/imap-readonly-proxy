// Command imap-readonly-proxy exposes upstream IMAP mailboxes read-only.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/arj/imap-readonly-proxy/internal/config"
	"github.com/arj/imap-readonly-proxy/internal/proxy"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		os.Exit(hashPassword())
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	cfgPath := flag.String("config", "config.toml", "path to the configuration file")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintln(os.Stderr, "invalid -log-level:", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("cannot load configuration", "err", err)
		os.Exit(1)
	}
	if fi, err := os.Stat(*cfgPath); err == nil && fi.Mode().Perm()&0o007 != 0 {
		log.Warn("configuration file is accessible by others; it contains upstream credentials", "mode", fi.Mode().Perm().String())
	}

	srv := proxy.New(cfg, log, nil)
	ln, err := srv.Listen()
	if err != nil {
		log.Error("cannot listen", "err", err)
		os.Exit(1)
	}
	log.Info("listening", "version", version, "addr", ln.Addr().String(), "tls", !cfg.Server.InsecurePlaintext)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Info("shutting down")
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// hashPassword reads a password (from the terminal without echo, or from
// stdin) and prints its bcrypt hash for local_password_hash.
func hashPassword() int {
	var pw []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		pw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		var line string
		line, err = bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line != "" {
			err = nil
		}
		pw = []byte(strings.TrimRight(line, "\r\n"))
	}
	if err != nil || len(pw) == 0 {
		fmt.Fprintln(os.Stderr, "no password given")
		return 1
	}
	h, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(string(h))
	return 0
}
