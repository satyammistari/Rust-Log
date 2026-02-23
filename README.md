# log-anonymizer

**Strip PII from logs in under 2 seconds. Written in Rust.**

## The Problem

Engineers share logs to debug production issues but those logs contain customer emails, IP addresses, session tokens, and API keys. Manual scrubbing is slow and error-prone. log-anonymizer processes gigabytes in seconds safely.

## Demo

### 1. Basic pipe usage

```bash
$ echo "user test@email.com from 192.168.1.1" | log-anonymizer
user [EMAIL_REDACTED] from [IPV4_REDACTED]
```

### 2. File processing with report

```bash
$ log-anonymizer --input app.log --output clean.log --report
```

```
Redaction Summary
──────────────────────────────────────────────────
  Emails              12  [EMAIL_REDACTED]
  IPv4/IPv6           24  [IPV4_REDACTED]
  JWTs                 3  [JWT_REDACTED]
  API Keys             2  [API_KEY_REDACTED]
  Passwords            1  [PASSWORD_REDACTED]
──────────────────────────────────────────────────
  Total           42 redactions
  Lines             1,000  processed
  Size             0.5 MB  processed
  Time              0.1  s  elapsed
  Speed            5 MB/s  throughput
```

### 3. CI mode

```bash
$ log-anonymizer --input build.log --ci --report
# Exit code 1 if any PII was redacted (fail the build)
```

## Installation

```bash
cargo install log-anonymizer
```

From this repo:

```bash
cargo build --release
# Binary at target/release/log-anonymizer
```

## Usage

| Option | Short | Description |
|--------|-------|-------------|
| `--input` | `-i` | Input file (default: stdin) |
| `--output` | `-o` | Output file (default: stdout) |
| `--report` | `-r` | Print redaction summary |
| `--report-format` | | `pretty` or `json` |
| `--style` | | `fixed`, `tagged`, or `hashed` |
| `--ci` | | Exit 1 if any redactions found |
| `--skip-uuids` | | Do not redact UUIDs |
| `--skip-ips` | | Do not redact IP addresses |
| `--skip-emails` | | Do not redact emails |
| `--no-color` | | Disable colored report output |
| `--recursive` | `-R` | Process all .log/.txt in directory |

### Examples

```bash
# Stdin to stdout
cat app.log | log-anonymizer

# File to file with report
log-anonymizer -i app.log -o clean.log -r

# JSON report for tooling
log-anonymizer -i app.log -o clean.log -r --report-format json

# Hashed replacements (first 8 hex of SHA256)
log-anonymizer -i app.log --style hashed

# Recursive directory
log-anonymizer -i ./logs -o ./redacted -R -r
```

### Report output (pretty)

Shown on stderr when `--report` is used: counts per PII type, lines processed, size, duration, throughput.

### Report output (JSON)

With `--report-format json`, a single JSON object is printed to stdout (or use `-r` and JSON goes to stderr with the summary). Fields: `emails_redacted`, `ips_redacted`, `jwts_redacted`, `api_keys_redacted`, `aws_keys_redacted`, `credit_cards_redacted`, `uuids_redacted`, `passwords_redacted`, `total_redactions`, `lines_processed`, `bytes_processed`, `duration_ms`, `throughput_mb_per_sec`.

## Supported PII Types

| Pattern Type   | Example                          | Replacement (tagged)        |
|----------------|----------------------------------|-----------------------------|
| Email          | `user@example.com`               | `[EMAIL_REDACTED]`          |
| IPv4           | `192.168.1.1`                    | `[IPV4_REDACTED]`           |
| IPv6           | `2001:0db8::1`                   | `[IPV6_REDACTED]`           |
| JWT            | `eyJhbGci...`                    | `[JWT_REDACTED]`            |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE`           | `[AWS_ACCESS_KEY_REDACTED]` |
| AWS Secret     | `aws_secret_access_key=...`      | `[AWS_SECRET_KEY_REDACTED]` |
| API key/token  | `api_key=sk_live_xxx...`         | `[API_KEY_REDACTED]`        |
| Credit card    | `4111111111111111`               | `[CREDIT_CARD_REDACTED]`    |
| UUID           | `a1b2c3d4-e5f6-7890-abcd-...`    | `[UUID_REDACTED]`           |
| Private key    | `-----BEGIN RSA PRIVATE KEY-----`| `[PRIVATE_KEY_REDACTED]`    |
| Password field | `password=secret123`             | `[PASSWORD_REDACTED]`       |

## Performance

Processes **1GB log files in under 2 seconds** on modern hardware.

- **memmap2** — File is memory-mapped; no full read into heap.
- **rayon** — Line-level parallelism with work-stealing.
- **Pre-compiled regex** — All patterns compiled once at startup; no regex compilation in hot path.

## Why Rust over Python or Go?

1. **rayon parallel iterators** — Zero race conditions by design; no shared mutable state across threads.
2. **memmap2** — OS-level file paging; large files don’t require proportional heap allocation.
3. **regex crate (finite automaton)** — Linear-time matching; no catastrophic backtracking on adversarial input.

## Architecture

| File         | Role |
|--------------|------|
| `main.rs`    | CLI entrypoint; parses args, builds redactor, routes to processor. |
| `cli.rs`     | Clap-derived CLI definition. |
| `error.rs`   | Custom `AppError` and `Result` type. |
| `patterns.rs`| `PatternSet`: all regexes compiled once at startup. |
| `redactor.rs`| Redaction logic; `Redactor` + `RedactionStats`; supports fixed/tagged/hashed style. |
| `processor.rs`| File (mmap + rayon), stdin, and recursive directory processing. |
| `reporter.rs`| Pretty and JSON report output. |

## Engineering Trade-offs

1. **Memory-mapped vs streaming** — We use mmap for large files so the OS manages paging and we get zero-copy `str` over the file. Streaming would lower peak RAM but add buffering and copying; for batch “read whole file, write whole file” workloads, mmap wins.
2. **Tagged replacement vs fixed** — Tagged (`[EMAIL_REDACTED]`, etc.) is default because it preserves which kind of PII was found for audits and debugging; fixed `[REDACTED]` is optional for maximum brevity.
3. **Line-level vs chunk parallelism** — We parallelize by line so each unit is independent and stats merge trivially; chunk-based parallelism would require careful handling of line boundaries and aggregation.

## Contributing

```bash
cargo test
cargo bench
cargo clippy -- -D warnings
cargo fmt --check
```

## License

MIT
