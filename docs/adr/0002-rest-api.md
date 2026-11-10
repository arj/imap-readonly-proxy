# ADR 0002: Read-only REST API on top of the IMAP policy

Status: accepted
Date: 2026-11-10

## Context

Some consumers, such as scripts, automation tools and AI agents, find HTTP
and JSON easier to use than IMAP. The REST API must keep the read-only
guarantee of ADR 0001. It must also not add a second, independent command
path that could drift from the IMAP policy.

## Decision

1. **Same policy path.** Each REST request is translated into IMAP client
   commands. Those commands are rendered to wire bytes and passed through the
   same reader, tokenizer and policy as commands from IMAP clients
   (`restapi/gateway.go`). Only the policy's re-encoded command is sent
   upstream. In addition, the REST layer only allows these policy actions:
   EXAMINE, STATUS, LIST, FETCH and SEARCH. As a result:
   - SELECT becomes EXAMINE.
   - Body fetches use BODY.PEEK, so `\Seen` is never set.
   - Write commands are impossible, even if the REST code had a bug.
2. **GET only.** There are no routes for other methods, so they get 405.
   Mail content is never rendered by browsers:
   - Attachments are served as `application/octet-stream` with
     `Content-Disposition: attachment`.
   - Raw messages are served as `message/rfc822`, also as attachment.
   - Every response sets `nosniff`, a CSP that blocks all content
     (`default-src 'none'; sandbox`) and `Cache-Control: no-store`.
3. **Bearer tokens instead of passwords.**
   - Tokens are random (256 bits) and stored as SHA-256 hashes
     (`api_token_sha256`). A hash lookup is cheap, so per-request
     authentication does not become a bcrypt-based CPU DoS.
   - Tokens are compared in constant time against all accounts.
   - Failed attempts count towards a per-IP lockout (10 failures in
     15 minutes).
4. **One upstream connection per request.** This keeps the REST side
   stateless: no shared selected-mailbox state between requests, and no
   long-lived credentials in memory beyond the configuration. The cost is
   latency per request, from TLS and LOGIN. Concurrency is limited in total
   and per IP.
5. **Bounded resources.**
   - Message bodies are buffered up to `max_message_bytes` (default 25 MiB).
   - Larger messages get 413.
   - MIME processing is limited in depth and in number of parts.
   - Other upstream responses are limited to 2 MiB.
6. **Mailbox names.**
   - The API uses UTF-8 names, converted to and from IMAP modified UTF-7.
   - Only canonical encodings are accepted, so a name cannot have two
     forms.
   - Folder filters apply to the IMAP name, as for IMAP clients. Hidden and
     nonexistent folders both get 404.
7. **Independent endpoints.**
   - `[server]` (IMAP) and `[http]` (REST) can each be switched off with
     `enabled = false`, or by omitting `listen`.
   - A switched-off section is not validated.
   - The proxy refuses to start if both are switched off, or if an account
     has no credentials for any enabled endpoint.

## Consequences

- The REST API can only do what the IMAP policy allows, so the ADR 0001
  tests and fuzzing cover it as well.
- No IDLE or push notifications; clients poll.
- Pagination uses UIDs (`before_uid`), and `uidvalidity` is returned so
  clients can detect a renumbered mailbox.
- Behind a reverse proxy, all clients share the reverse proxy's IP for
  rate limiting, because `X-Forwarded-For` is not trusted.
