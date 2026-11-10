# ADR 0001: Parse and re-encode client commands against an allowlist

Status: accepted
Date: 2026-11-10

## Context

The goal is to give an IMAP client read-only access to a mailbox on a server
that cannot enforce read-only access itself, such as a hosted mailbox without
ACL support. A review of
[esukram/imap-proxy](https://github.com/esukram/imap-proxy) (commit `5fa7455`)
showed that line-based passthrough filtering with a denylist can be bypassed in
several ways:

- Framing desynchronisation. The literal marker `{+N}` was accepted by the
  proxy's parser (`strconv.ParseInt` accepts a sign) but not by servers. The
  next N bytes were then forwarded unfiltered and run upstream as a new
  command. Sync literals were forwarded even after the server rejected the
  command.
- Unfiltered modes. IDLE forwarded everything until `DONE`, `COMPRESS DEFLATE`
  turned the filter off, and lines that failed to parse were forwarded raw.
- Denylist gaps. SETACL, DELETEACL, SETMETADATA, SETQUOTA, REPLACE and
  UNAUTHENTICATE were not blocked. `CLOSE` expunged messages flagged
  `\Deleted`, and `FETCH BODY[]` / `RFC822` set `\Seen`.

The common root cause is that the proxy forwards bytes it has not fully
understood. The server's view of those bytes can differ from the proxy's.

## Decision

1. Every client command is read completely, including all literals, with
   strict framing before anything is sent upstream: CRLF only, no NUL or
   bare CR/LF, a literal marker of digits only with an optional `+`, and
   size limits. A framing error closes the connection.
2. The command is tokenized and parsed against a fixed grammar for an
   allowlist of read-only commands: CAPABILITY, NOOP, LOGOUT, LOGIN,
   SELECT/EXAMINE, STATUS, LIST, LSUB, NAMESPACE, FETCH, SEARCH (and UID
   forms), CLOSE/UNSELECT, IDLE. Each argument is validated, including search
   keys, fetch attributes, sections and sequence sets.
3. The upstream command is newly encoded from the parsed structure by the
   proxy, under the proxy's own tags. Raw client bytes are never forwarded.
   Mutating forms are rewritten: SELECT becomes EXAMINE, CLOSE becomes
   UNSELECT (or is only sent while the mailbox was opened with EXAMINE, where
   CLOSE does not expunge), and `BODY[...]` becomes `BODY.PEEK[...]`.
   `RFC822` and `RFC822.TEXT` are rejected because they have no PEEK form.
4. During IDLE, the only input accepted is `DONE`. Anything else ends the
   session.
5. Extensions that change framing or state are not offered: COMPRESS,
   STARTTLS (client side), ENABLE, CONDSTORE/QRESYNC, NOTIFY, AUTHENTICATE.
   Upstream CAPABILITY responses are replaced by the proxy's own list.
6. Folder filtering is applied to the parsed mailbox name, so quoting,
   literals and case variants cannot get around it. LIST/LSUB responses are
   filtered on the server's response, and responses the proxy cannot parse
   are dropped (fail closed).

## Consequences

- A write would need a bug in the proxy's own encoder, not a disagreement
  between two parsers. A fuzz test checks that every accepted command encodes
  to an allowlisted verb, never contains a non-PEEK body fetch, and re-parses
  to the same encoding.
- Some valid client behaviour is lost: SASL AUTHENTICATE, CONDSTORE/QRESYNC
  sync, SORT/THREAD, and BINARY fetch. Clients have to fall back to plain
  IMAP4rev1, which common clients support.
- Each new command or extension is a deliberate change to the grammar, not a
  configuration option.
- The proxy holds the upstream credentials. Those credentials can still write
  if they are used elsewhere, so a server-side read-only account or ACL
  remains preferable where it is available.
