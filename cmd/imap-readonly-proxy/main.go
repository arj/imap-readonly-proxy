// Command imap-readonly-proxy exposes upstream IMAP mailboxes read-only.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/arj/imap-readonly-proxy/internal/restapi"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		os.Exit(hashPassword())
	}
	if len(os.Args) > 1 && os.Args[1] == "generate-token" {
		os.Exit(generateToken())
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

	var (
		imapSrv *proxy.Server
		api     *restapi.API
		errc    = make(chan error, 2)
		running = 0
	)
	if cfg.Server.IMAPEnabled() {
		imapSrv = proxy.New(cfg, log, nil)
		ln, err := imapSrv.Listen()
		if err != nil {
			log.Error("cannot listen (imap)", "err", err)
			os.Exit(1)
		}
		log.Info("imap listening", "version", version, "addr", ln.Addr().String(), "tls", !cfg.Server.InsecurePlaintext)
		running++
		go func() { errc <- imapSrv.Serve(ln) }()
	}
	if cfg.HTTP.IsEnabled() {
		api = restapi.New(cfg, log, nil)
		ln, err := api.Listen()
		if err != nil {
			log.Error("cannot listen (http)", "err", err)
			os.Exit(1)
		}
		log.Info("rest api listening", "version", version, "addr", ln.Addr().String(), "tls", !cfg.HTTP.InsecurePlaintext)
		running++
		go func() { errc <- api.Serve(ln) }()
	}

	if imapSrv == nil {
		log.Info("imap endpoint switched off")
	}
	if api == nil {
		log.Info("rest endpoint switched off")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	shutdown := func() {
		if imapSrv != nil {
			imapSrv.Close()
		}
		if api != nil {
			api.Close()
		}
	}
	exit := 0
	select {
	case <-sig:
		log.Info("shutting down")
	case err := <-errc:
		running--
		if err != nil {
			log.Error("server stopped", "err", err)
			exit = 1
		}
	}
	shutdown()
	for ; running > 0; running-- {
		if err := <-errc; err != nil {
			log.Error("server stopped", "err", err)
		}
	}
	os.Exit(exit)
}

// generateToken prints a new random REST API token and the matching
// api_token_sha256 value for the configuration.
func generateToken() int {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	token := "irp_" + base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(token))
	fmt.Fprintln(os.Stderr, "Give this token to the API client (it is shown only once):")
	fmt.Println(token)
	fmt.Fprintln(os.Stderr, "Add this line to the [[accounts]] entry:")
	fmt.Printf("api_token_sha256 = %q\n", hex.EncodeToString(sum[:]))
	return 0
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
