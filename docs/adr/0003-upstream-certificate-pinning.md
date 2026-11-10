# ADR 0003: Certificate pinning for self-signed upstream servers

Status: accepted
Date: 2026-11-10

## Context

The proxy verifies the upstream server's certificate against the system CAs
(or `remote_ca_file`), including host name and validity period. Many
private IMAP servers (NAS devices, home servers) use self-signed certificates. `remote_ca_file` can
trust such a certificate only if it lists the connected name in
`subjectAltName` and has not expired; Go rejects certificates that carry
the name only in the Common Name. Users need a way to connect to these
servers without turning verification off, because an unverified connection
would expose the upstream password to anyone who can intercept it.

## Decision

1. **Pin the leaf certificate.** A new account option
   `remote_tls_cert_sha256` holds the SHA-256 of the DER-encoded leaf
   certificate, the value `openssl x509 -fingerprint -sha256` prints. If it
   is set, the TLS client replaces the standard verification with an exact
   comparison of the presented leaf certificate against the pin
   (`tls.Config.VerifyConnection`, which runs even though
   `InsecureSkipVerify` is set to disable the standard check). Issuer, names
   and expiry are not checked: the pin is the trust decision.
2. **No "skip verification" option.** There is deliberately no setting that
   accepts any certificate.
3. **Pin and CA file are mutually exclusive**, and the pin is rejected for
   `insecure-plaintext`, so the active trust model is always unambiguous.
4. **Fail closed.** A mismatch aborts the handshake before LOGIN; the error
   shows the presented fingerprint so that a legitimate certificate change
   can be diagnosed.
5. **Helper subcommand.** `upstream-cert` connects (TLS or STARTTLS), shows
   the certificate chain, the result of the standard verification and the
   line to pin. It sends no credentials. The documentation tells users to
   compare the fingerprint with the certificate on the server, because the
   first connection could itself be intercepted.

## Alternatives considered

- **Pin the public key (SPKI) instead of the certificate.** Survives
  re-issuing a certificate with the same key, but cannot be checked with
  the common `openssl x509 -fingerprint` command, and many self-signed
  setups generate a new key with each certificate. Rejected for usability.
- **Several pins** for a rollover. Not needed for a single upstream server
  yet; can be added later as a list without changing the semantics.
- **`insecure_skip_verify`.** Rejected (see 2).

## Consequences

- Self-signed upstream servers work with full protection against
  interception, as long as the pin was verified out of band.
- When the server's certificate changes, the proxy stops connecting until
  the pin is updated. This is intended.
- An expired pinned certificate keeps working. Expiry of a self-signed
  certificate does not weaken a pin.
