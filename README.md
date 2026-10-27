# php2shell-scanner

A Go command-line tool for detecting signs of **CVE-2026-109618** and
**CVE-2026-109619** in PHP applications. Uses multipart probes and response
comparison to identify potential exposure. No external Go dependencies.

## How It Works

The scanner sends a minimal multipart control request followed by up to three
crafted multipart probes. The probes use PHP array keys nested **62 levels** deep
and increase from **1 MiB to 20 MiB**. Regression tests verify the contents
of all three probe payloads.

It checks for PHP memory-exhaustion errors, differential empty HTTP 500 responses,
and possible PHP-FPM worker failures. An advertised PHP version is also assessed
against the initial fixed releases: **8.2.35, 8.3.36, 8.4.27, and 8.5.12**.
An initially failing control and a nonempty HTTP 500 without the PHP fatal-error
signature are not treated as crash signals. Rejected probes can still produce a
version-based assessment when PHP advertises a known release.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved;
`--path` and `--path-file` test custom paths. phpMyAdmin responses are automatically
retested at `/show_config_errors.php`. Redirects require `--follow-redirects`.

### SAPI Modes

The default `--sapi auto` applies both mod_php and PHP-FPM signal rules.
Use `--sapi mod_php` or `--sapi fpm` for a known server configuration. Gateway
failures and differential empty HTTP 200 responses are PHP-FPM signals; memory
exhaustion and differential empty HTTP 500 responses apply to both modes.

### Network Impact

**Scanning is active by default.** Each tested path may receive a **42-byte control**
and three probes totaling approximately **29 MiB**. These requests may exhaust PHP
memory or interrupt workers. Probing stops once the verdict is settled; duplicate
normalized URLs are scanned once. Use only on systems you are authorized to test.

Add `--passive` to send a GET/version check instead of multipart probes.

Probe uploads use `Expect: 100-continue` so a server can reject a large request
before receiving its body. If the server does not respond to the handshake,
uploading starts after one second. Connection failures without a complete HTTP
response remain inconclusive.

## Requirements

- Go **1.22+** to build or install.
- A reachable HTTP or HTTPS application endpoint.

## Installation

```sh
go install -v github.com/tal7aouy/php2shell-scanner/cmd/php2shell@latest
```

Ensure Go's binary directory is on your `PATH`: `go env GOBIN`, or
`$(go env GOPATH)/bin` when `GOBIN` is unset. The latest changes must be published
to GitHub before they can be installed with `@latest`.

Or build from source:

```sh
go build -o php2shell ./cmd/php2shell
./php2shell -u https://example.com
```

### Check or Update an Installed Build

```sh
php2shell --version
go version -m "$(command -v php2shell)"
```

Older builds may default to version-only checks and lack `--version`. If the
installed binary still suggests adding `-active`, install the current local
source from this project's directory:

```sh
go install ./cmd/php2shell
php2shell --version
```

If multiple binaries are installed, use `type -a php2shell` to inspect your
`PATH`. To install the published development branch explicitly:

```sh
go install -v github.com/tal7aouy/php2shell-scanner/cmd/php2shell@main
```

Local uncommitted changes are included only in a local build or installation.
The `--version` output identifies the module version or Git revision when
available, marks uncommitted builds, and states the default scan mode.

### Docker

```sh
docker build -t php2shell-scanner .
docker run --rm php2shell-scanner -u https://example.com
```

Mount a directory to read target lists and write results:

```sh
docker run --rm -v "$PWD:/data" -w /data \
  php2shell-scanner -l hosts.txt -o results.json --all-results
```

The container runs as UID `65532`. Mounted output directories must be writable
by that user.

## Usage

Scan a single host or a list, and save findings:

```sh
php2shell -u https://example.com
php2shell -l hosts.txt
php2shell -l hosts.txt -t 20 -o findings.json
```

Target and path files contain one entry per line. Blank lines and `#` comments
are ignored. Use `-l -` to read targets from stdin.

Add headers, use custom paths, or restrict SAPI rules:

```sh
php2shell -u https://example.com -H 'Authorization: Bearer token' -H 'Cookie: session=abc'
php2shell -u https://example.com --path /phpinfo.php
php2shell -u https://example.com --path /index.php --path /admin.php
php2shell -u https://example.com --path-file paths.txt
php2shell -u https://example.com --sapi fpm
```

Follow redirects, inspect evidence, or run a passive check:

```sh
php2shell -u https://example.com --follow-redirects --verbose
php2shell -l hosts.txt --timeout 90 -o results.json --all-results
php2shell -u https://example.com --passive
```

Use `./php2shell` instead of `php2shell` when running a local build.

## Options

| Option | Description |
| --- | --- |
| `-u`, `--url` | Single target URL |
| `-l`, `--list` | Target file, one URL per line; `-` for stdin |
| `-t`, `--threads` | Concurrent targets, 1–256; default `10` |
| `--timeout` | Seconds or duration (`60` or `60s`); default `60s` |
| `-o`, `--output` | New JSON report file; existing files are not overwritten |
| `--all-results` | Save every result instead of findings only |
| `-k`, `--insecure` | Disable TLS certificate verification |
| `--follow-redirects` | Follow up to 10 redirects, preserving POST bodies |
| `-H`, `--header` | Custom header; repeatable, including a Host override |
| `-v`, `--verbose` | Show redacted HTTP evidence |
| `-q`, `--quiet` | Print finding URLs only |
| `--no-color` | Disable terminal colors |
| `--sapi` | `auto`, `mod_php`, or `fpm`; default `auto` |
| `--path` | Custom application path; repeatable |
| `--path-file` | Path file; choose either this or `--path` |
| `--passive` | GET/version check only; no multipart probes |
| `--active` | Accepted for compatibility; active mode is already the default |
| `-h`, `--help` | Show help |
| `--version` | Show installed version, revision, and default scan mode |

Timeouts cover each exchange and its redirects. Query parameters are preserved;
URLs without a scheme use HTTPS. Known credential headers and Host overrides are
removed across origins, including subsequent probes. Colors are disabled when
output is redirected or `NO_COLOR` is set.

## Output

Results go to stdout; progress and the summary go to stderr. Each result includes
the verdict, tested endpoint, last HTTP status, reason, and SAPI signal family
when applicable.

| Verdict | Meaning |
| --- | --- |
| `SUSPECTED` | A multipart probe produced a failure signal; verify the installed PHP package |
| `POTENTIALLY_VULNERABLE` | The advertised PHP release predates upstream fixes; verify vendor backports |
| `PATCHED_VERSION` | The advertised release includes the initial fixes |
| `NO_SIGNAL` | Three probes produced no failure signal; patch status remains unknown |
| `UNKNOWN` | A passive check could not establish the PHP version |
| `INCONCLUSIVE` | A control or probe was unsuitable, blocked, canceled, or failed |
| `ERROR` | The initial exchange failed or the input was invalid |

With `-o`, findings are saved as JSON with verdict reasons, timestamps, per-path
results, and redacted HTTP evidence. Add `--all-results` to retain unsuccessful
checks as well. Reports use permissions `0600` and input order.

Authorization, cookies, API-key, and token/secret/password headers are redacted.
Response excerpts and URL queries may still contain secrets; review reports
before sharing. Excerpts are limited to 2 KiB and response bodies to 1 MiB after
decompression. Upload counters describe bytes read by the transport, not verified
receipt by the server. HTTP dumps describe the logical exchange.

Exit codes: `0` for all patched-version results, `1` for findings, `2` for
incomplete/no-signal assessments or input/report errors, and `130` for interruption.
Findings take precedence over incomplete results; input/report errors return `2`.

## Limitations

Memory exhaustion and gateway failures are **indicators, not confirmation of RCE**.
Patched and vulnerable PHP can produce the same empty HTTP 500 response. The
upstream scanner documentation reports this on patched PHP 8.4.27 with
`memory_limit` from **2M to 32M**, and PHP 8.3.36 at **128M** when
`max_multipart_body_parts` is **2785 or higher**. Thresholds vary by build; these
configurations have not been independently reproduced in this repository.

When PHP hides its version, the scanner cannot reliably distinguish these cases.
Verify findings against the installed package and vendor backports. A version
banner alone does not establish the running build, and `NO_SIGNAL` does not prove
safety or even that the endpoint uses PHP.

The scanner uses conservative verdict labels and stops before sending large
probes when the control returns a redirect,
blocked request, or missing page. Supply a working PHP endpoint. PHP's October 23,
2026 upload-progress follow-up requires configuration checks that remote banners
cannot verify; consult the [PHP announcements](https://www.php.net/).

## Development

```sh
go test -race ./...
go vet ./...
```

[CI](https://github.com/tal7aouy/php2shell-scanner/actions/workflows/ci.yml) checks
formatting, static analysis, race-enabled tests, coverage, installation, and Docker.
It covers stable Go on Linux, macOS, and Windows, plus Go 1.22 on Linux. Tests use
in-memory fixtures and local HTTP only; the wire test skips if listeners are
blocked. `.gitattributes` enforces LF line endings for Windows checkouts.

## Credits

Original PHP2Shell discovery: [Calif](https://calif.io/php2shell/).
Multipart probe logic is based on research by the Assetnote Security Research
Team for [Searchlight's Exposure Platform](https://www.slcyber.io/exposure).
Go implementation maintained by tal7aouy. Released under the [MIT license](LICENSE).
