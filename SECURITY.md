# Security policy

## Security goal

Clients authenticated by the proxy can read messages and folder metadata of
the configured upstream account, limited to the configured folders. They must
not be able to change any upstream state: flags (including `\Seen`), messages,
folders, subscriptions, ACLs, metadata or quotas.

## Out of scope

- An attacker who can read the configuration file or the process memory
  (upstream credentials).
- A malicious or compromised upstream server (the proxy limits response sizes
  but trusts response content).
- Denial of service beyond the built-in connection, size and time limits.
- Confidentiality of the client connection when `insecure_plaintext` is used
  (allowed only on loopback).

## Reporting

Please report vulnerabilities privately through GitHub security advisories on
this repository rather than in a public issue.
