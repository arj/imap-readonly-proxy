# imap-readonly-proxy

An IMAP proxy and HTTPS REST API that give clients **read-only** access to
an upstream mailbox.
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

## Endpoints

The proxy has two independent endpoints. Each can be switched on or off:

| Endpoint | Section | Switch off |
|---|---|---|
| IMAP (implicit TLS, port 993) | `[server]` | `enabled = false` or no `listen` |
| HTTPS REST API (JSON) | `[http]` | `enabled = false` or no `listen` |

- A switched-off section is not validated, so its settings can stay in the
  file.
- The proxy refuses to start if both endpoints are off.
- Every account needs credentials for at least one enabled endpoint:
  - IMAP: `local_password_hash`
  - REST: `api_token_sha256`
- On startup, the log shows which endpoints are listening and which are
  switched off.

## REST API

Each REST request is translated into IMAP commands and checked by the same
policy as IMAP clients. The API can therefore never write, set `\Seen` or
open hidden folders. See [ADR 0002](docs/adr/0002-rest-api.md).

The full API description is in OpenAPI 3.1 format at
[docs/openapi.yaml](docs/openapi.yaml) (installed by the Debian package as
`/usr/share/doc/imap-readonly-proxy/openapi.yaml`). It can be opened with
any OpenAPI viewer or used to generate clients. A unit test checks that it
lists exactly the routes the server implements.

Create a token, add the printed `api_token_sha256` line to the account, and
give the token to the client:

```sh
imap-readonly-proxy generate-token
curl -H "Authorization: Bearer irp_..." https://imap-proxy.example.org:8443/api/v1/mailboxes
```

All endpoints are `GET` (other methods get 405). Mailbox names are UTF-8
and must be percent-encoded in the path, including `/` (`%2F`).

| Path | Result |
|---|---|
| `/healthz` | `{"status":"ok"}`, without authentication |
| `/api/v1/mailboxes` | Visible mailboxes (`name`, `delimiter`, `flags`) |
| `/api/v1/mailboxes/{mailbox}` | `messages`, `unseen`, `uidnext`, `uidvalidity` |
| `/api/v1/mailboxes/{mailbox}/messages` | Message summaries, newest first |
| `/api/v1/mailboxes/{mailbox}/messages/{uid}` | Decoded message: headers, `text`, `html`, `attachments` |
| `/api/v1/mailboxes/{mailbox}/messages/{uid}/raw` | Original message (`message/rfc822`, as download) |
| `/api/v1/mailboxes/{mailbox}/messages/{uid}/attachments/{index}` | Decoded attachment (`application/octet-stream`, as download) |

Query parameters for `/messages`:

- **Filters**, combined with AND:
  - `from`, `to`, `cc`, `subject`, `body`, `text`: substring match; UTF-8
    is allowed.
  - `since`, `before`, `on`: `YYYY-MM-DD`.
  - `unseen`, `flagged`: `true` or `false`.
- **Pagination:**
  - `limit`: 1 to 200, default 50.
  - `before_uid`: pass the `next_before_uid` from the previous page.
- Unknown parameters get 400.

Example response for `/messages?limit=1`:

```json
{
  "mailbox": "INBOX", "uidvalidity": 1794340000, "total": 3,
  "messages": [{
    "uid": 3, "flags": [], "internal_date": "2026-11-09T10:00:00+01:00", "size": 245,
    "subject": "Message 3 Grüße", "from": [{"address": "a@example.com"}],
    "to": [{"address": "b@example.com"}], "date": "2026-11-09T10:00:00+01:00",
    "message_id": "<m3@example.com>"
  }],
  "next_before_uid": 3
}
```

Errors are JSON (`{"error": "..."}`):

| Status | Meaning |
|---|---|
| 400 | Invalid input |
| 401 | Missing or wrong token |
| 404 | Unknown or hidden mailbox or message |
| 405 | Method other than GET |
| 413 | Message larger than `max_message_bytes` |
| 429 | Too many failed attempts or concurrent requests |
| 502 | Upstream server unavailable |

Each request opens its own upstream connection, so every request includes
a TLS handshake and LOGIN to the upstream server.

## Usage

```sh
go build -trimpath -o imap-readonly-proxy ./cmd/imap-readonly-proxy
./imap-readonly-proxy hash-password          # prints a bcrypt hash
cp config.example.toml config.toml && chmod 600 config.toml   # then edit
./imap-readonly-proxy -config config.toml
```

Configuration (see [config.example.toml](config.example.toml)):

- Unknown keys are rejected.
- `[server]` (IMAP) and `[http]` (REST) can each be switched off; see
  [Endpoints](#endpoints).
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
| Client to proxy | `[server]` and `[http]` `tls_cert`, `tls_key` (may be the same files) | The proxy's own server certificate and private key, presented to IMAP clients (like any IMAPS server on port 993). |
| Proxy to upstream | `remote_security`, optional `remote_ca_file`, `remote_tls_server_name` | Verifies the upstream server's certificate. The proxy presents no certificate upstream. |

The certificate is not used to authenticate anyone, and the proxy does not
ask clients for certificates. Authentication is by password on both sides:

- IMAP clients log in to the proxy with `local_user` and the password
  matching `local_password_hash`. REST clients send a bearer token matching
  `api_token_sha256`.
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
- The REST API has no push or IDLE; clients poll. It does not trust
  `X-Forwarded-For`, so behind a reverse proxy all clients share one IP
  for rate limiting.
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
