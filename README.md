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
- The client listener needs `tls_cert`/`tls_key` (implicit TLS). Plaintext
  is only allowed on a loopback address.
- Upstream connections use `tls` or `starttls`, with certificate
  verification. `insecure-plaintext` is only allowed for a loopback upstream.
- The upstream password can be read from `remote_password_file`.

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
