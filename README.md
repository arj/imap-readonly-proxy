# imap-readonly-proxy

An IMAP proxy that gives clients **read-only** access to an upstream mailbox.
It is built for servers that cannot provide a read-only account or ACL
themselves, for example to give a mail-processing tool, an AI agent or a
backup job access to a mailbox without the ability to change it.

It was written after a review of
[esukram/imap-proxy](https://github.com/esukram/imap-proxy) found that
line-based denylist filtering can be bypassed (literal desync, IDLE
smuggling, COMPRESS, missing commands). See
[ADR 0001](docs/adr/0001-parse-and-reencode-allowlist.md) for the reasoning.

## How it works

- Clients log in to the proxy with a local user and password (bcrypt). The
  proxy then logs in upstream with separately configured credentials, so
  clients never see them.
- Each client command is read in full, with strict framing, and parsed
  against an allowlist grammar. The proxy then sends its own re-encoded
  version upstream. Client bytes are never passed through.
- Read-only rewrites:
  - `SELECT` becomes `EXAMINE`.
  - `CLOSE` becomes `UNSELECT`.
  - `BODY[...]` becomes `BODY.PEEK[...]`.
- `RFC822` and `RFC822.TEXT` are rejected, because they would set `\Seen`.
- Commands that write get `NO [NOPERM]`. Everything else unknown gets `BAD`.
- Optional folder allowlist or blocklist, enforced on commands and on
  LIST/LSUB responses.

Supported commands: `CAPABILITY`, `NOOP`, `LOGOUT`, `LOGIN`, `SELECT`,
`EXAMINE`, `STATUS`, `LIST`, `LSUB`, `NAMESPACE`, `FETCH`, `UID FETCH`,
`SEARCH`, `UID SEARCH`, `CLOSE`, `UNSELECT`, `IDLE`. `IDLE`, `NAMESPACE` and
`UNSELECT` are only offered if the upstream server supports them. `LITERAL+`
is offered to clients.

## Usage

```sh
go build -trimpath -o imap-readonly-proxy ./cmd/imap-readonly-proxy
./imap-readonly-proxy hash-password          # prints a bcrypt hash
cp config.example.toml config.toml && chmod 600 config.toml   # then edit
./imap-readonly-proxy -config config.toml
```

Configuration (see [config.example.toml](config.example.toml)):

- Unknown keys are rejected.
- The client listener needs `tls_cert`/`tls_key` (implicit TLS). This is
  the proxy's own server certificate; see [TLS certificates](#tls-certificates).
  Plaintext is only allowed on a loopback address.
- Upstream connections use `tls` or `starttls`, with certificate
  verification. `insecure-plaintext` is only allowed for a loopback upstream.
- The upstream password can be read from `remote_password_file`.

## TLS certificates

There are two TLS connections:

| Connection | Configured by | Purpose |
|---|---|---|
| Client to proxy | `[server]` `tls_cert`, `tls_key` | The proxy's own server certificate and private key, presented to IMAP clients (like any IMAPS server on port 993). |
| Proxy to upstream | `remote_security`, optional `remote_ca_file`, `remote_tls_server_name` | Verifies the upstream server's certificate. The proxy presents no certificate upstream. |

The certificate is not used to authenticate anyone, and the proxy does not
ask clients for certificates. Authentication is by password on both sides:

- Clients log in to the proxy with `local_user` and the password matching
  `local_password_hash`.
- The proxy logs in upstream with `remote_user` and `remote_password` (or
  `remote_password_file`).

The certificate's name must match the hostname clients connect to. The
certificate file may contain the full chain (leaf first). The key must not
be encrypted. The files are read at startup, so restart the service after
replacing them.

### Option 1: Let's Encrypt (public hostname)

Use this if clients connect via a DNS name that resolves to the proxy and
port 80 is reachable from the internet during issuance and renewal.

```sh
sudo apt install certbot
sudo tee /usr/local/sbin/imap-readonly-proxy-cert-hook >/dev/null <<'HOOK'
#!/bin/sh
set -e
install -m 0640 -g imap-readonly-proxy "$RENEWED_LINEAGE/fullchain.pem" /etc/imap-readonly-proxy/cert.pem
install -m 0640 -g imap-readonly-proxy "$RENEWED_LINEAGE/privkey.pem"   /etc/imap-readonly-proxy/key.pem
systemctl restart imap-readonly-proxy
HOOK
sudo chmod 0755 /usr/local/sbin/imap-readonly-proxy-cert-hook
sudo certbot certonly --standalone -d imap-proxy.example.org \
  --deploy-hook /usr/local/sbin/imap-readonly-proxy-cert-hook
```

certbot stores the hook in the certificate's renewal configuration and runs
it after each renewal. The hook copies the files because
`/etc/letsencrypt/live` is not readable by the service user. A restart
closes open client connections, and clients reconnect. If port 80 is not
available, use a DNS challenge plugin for your DNS provider instead of
`--standalone`.

### Option 2: self-signed (LAN, single host, testing)

```sh
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 825 -subj "/CN=imap-proxy.lan" \
  -addext "subjectAltName=DNS:imap-proxy.lan,IP:192.168.1.10" \
  -keyout /etc/imap-readonly-proxy/key.pem -out /etc/imap-readonly-proxy/cert.pem
sudo chgrp imap-readonly-proxy /etc/imap-readonly-proxy/key.pem /etc/imap-readonly-proxy/cert.pem
sudo chmod 0640 /etc/imap-readonly-proxy/key.pem /etc/imap-readonly-proxy/cert.pem
```

Replace the name and IP in `subjectAltName` with the ones clients use.
Clients will not trust this certificate by default. Import `cert.pem` as a
trusted certificate in each client, or pass it as the CA file, for example
`openssl s_client -connect imap-proxy.lan:993 -CAfile cert.pem`. Do not
disable certificate verification in clients, because that removes the
protection against interception. The certificate expires after 825 days,
so create a new one before then. For several hosts, a small private CA
(for example with `step-ca` or `mkcert`) is easier to manage than
individual self-signed certificates.

### Proxy only reachable from the same host

If the proxy and its clients run on the same machine, you can skip the
certificate. Set `listen = "127.0.0.1:1143"` and `insecure_plaintext = true`.
Plaintext is rejected for any address other than loopback.

## Debian package

Pushing a tag of the form `vX.Y.Z` runs the tests and creates a GitHub
release with `.deb` packages for amd64, arm64 and armhf, plus `SHA256SUMS`.
To build a package locally, run `./packaging/build-deb.sh X.Y.Z amd64`.

The package installs:

- `/usr/bin/imap-readonly-proxy`
- a hardened systemd unit, `imap-readonly-proxy.service`
- a system user, `imap-readonly-proxy`
- the directory `/etc/imap-readonly-proxy` (mode `0750`, group
  `imap-readonly-proxy`)

The service is enabled on install, but only starts once a configuration
exists:

```sh
sudo apt install ./imap-readonly-proxy_X.Y.Z_amd64.deb
sudo install -m 0640 -g imap-readonly-proxy \
  /usr/share/doc/imap-readonly-proxy/config.example.toml \
  /etc/imap-readonly-proxy/config.toml          # then edit
sudo systemctl start imap-readonly-proxy
journalctl -u imap-readonly-proxy
```

The TLS key, certificate and `remote_password_file` must be readable by the
`imap-readonly-proxy` group. Place them in `/etc/imap-readonly-proxy`, for
example. The unit can bind to port 993 without running as root.
`apt purge` removes the configuration and the user.

## Hardening

- Limits per command:

  | Limit | Value |
  |---|---|
  | Line | 8 KiB |
  | Literal | 16 KiB |
  | Command | 64 KiB |
  | Literals per command | 16 |
  | Search nesting depth | 16 |
  | Search keys | 128 |

- Timeouts:

  | Phase | Timeout |
  |---|---|
  | Before login | 60 s |
  | After login, including IDLE | 30 min |
  | Writes | 10 min |

- Connection limits: 64 in total and 8 per IP by default.
- Login protection:
  - Constant-work bcrypt check, also for unknown users.
  - 1 s delay after a failed login, and disconnect after 3 failures.
  - Lockout for an IP after 10 failures in 15 minutes.

## Limitations

These are deliberate, to keep the attack surface small:

- No `AUTHENTICATE` (SASL). Clients must use `LOGIN` over TLS.
- No `STARTTLS` on the client side. Use implicit TLS, or plaintext on
  loopback.
- No `COMPRESS`, `ENABLE`, `CONDSTORE`/`QRESYNC`, `SORT`/`THREAD`,
  `BINARY`, `NOTIFY` or `ID`.
- No writable folders. The upstream credentials still have write access,
  so a read-only account or ACL on the server remains the stronger control
  where one is available.

## Tests

```sh
go test ./...                 # unit tests
make fuzz                     # fuzzes the policy invariant
./test/e2e/run.sh             # needs dovecot 2.4; starts a throwaway instance on 127.0.0.1
```

The end-to-end suite runs about 50 write attempts through the proxy against a
real Dovecot instance. They include all bypasses known for esukram/imap-proxy,
literal and IDLE smuggling, COMPRESS, ACL/metadata/quota commands and
`\Seen` side effects. The suite then checks that the upstream state (folders,
subscriptions, messages, flags) is unchanged.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
