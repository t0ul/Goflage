# goflage

Dependency-free PII & secret scrubber in Go — a pure-stdlib, single-binary
alternative to Microsoft Presidio for the deterministic, high-precision cases.
Part of the **fleet** of Go-native AI-security tools.

Detects and redacts: emails, IPv4 addresses, **Luhn-validated** credit cards,
AWS access keys, env-style secret assignments, API tokens (`sk-`/`ghp_`/`xox…`),
JWTs, and bearer tokens. Named-entity recognition (PERSON, LOCATION, …) is out
of scope by design — that belongs behind a served model; goflage owns the fast,
checksum-backed, zero-dependency recognizers.

## Use

```go
clean, findings := goflage.New().Scrub(text)
// findings is a telemetry-safe summary (entity types + counts, never values)
```

CLI:

```sh
echo "contact jane@example.org, key AKIAIOSFODNN7EXAMPLE" | go run ./cmd/goflage
```

## Design notes

- **Checksum gate** (Luhn) on credit cards → far fewer false positives than regex-only.
- **Overlap resolution** keeps the strongest match on conflict.
- **Log the `Finding`, never the `Match`** — the audit trail must not become the leak.

Zero third-party dependencies (stdlib `regexp` only).
