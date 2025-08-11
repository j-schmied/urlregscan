# URL Regex Scanner

A small, standard-library Python tool that fetches a URL and searches its textual content with a regular expression — with safety in mind.

> File: `url_regex_scanner.py` • Python 3.8+

---

## Features

* **Security by default**

  * Only `http`/`https` schemes
  * Blocks private / loopback / link-local / multicast / reserved IPs (SSRF mitigation)
  * Content-Type allow-list (`text/*`, `application/json|xml|javascript`)
  * Download **size cap** (default 5 MB) and **HTTP timeout**
  * Decompresses `gzip` / `deflate` safely
* **Regex safety**

  * Entire search runs under a **hard timeout** (separate thread) to curb catastrophic backtracking
  * Optional flags: `-i` (IGNORECASE), `-m` (MULTILINE), `-s` (DOTALL), `-x` (VERBOSE)
  * Match count cap
* **Clean engineering**

  * Strict typing (mypy-friendly), dataclasses for results
  * No third-party dependencies (pure stdlib)
  * Clear exit codes and machine-readable JSON output

---

## Quick start

```bash
python url_regex_scanner.py https://example.com "(?i)example"
```

With JSON output and a higher size cap:

```bash
python url_regex_scanner.py --json --max-bytes 2000000 https://example.com "\bex(am|em)ple\b"
```

Allow private targets (e.g. for *local* testing — disabled by default):

```bash
python url_regex_scanner.py --allow-private http://127.0.0.1:8000 "token=[0-9a-f]+"
```

---

## Installation

No package install required. Clone your repo and run the script with Python 3.8+.

```bash
python --version
# Python 3.8+ recommended

# optional: create a venv for tools like mypy/ruff/pytest
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip mypy ruff pytest
```

---

## CLI usage

```text
usage: url_regex_scanner.py [-h] [-i] [-m] [-s] [-x]
                            [--http-timeout HTTP_TIMEOUT]
                            [--re-timeout RE_TIMEOUT]
                            [--max-bytes MAX_BYTES]
                            [--max-matches MAX_MATCHES]
                            [--allow-private] [--json]
                            url pattern
```

**Arguments**

* `url` – Target URL (`http`/`https`)
* `pattern` – Regular expression

**Options**

* `-i, --ignore-case` – `re.IGNORECASE`
* `-m, --multiline` – `re.MULTILINE`
* `-s, --dotall` – `re.DOTALL`
* `-x, --verbose` – `re.VERBOSE`
* `--http-timeout <s>` – HTTP timeout (default: 10.0)
* `--re-timeout <s>` – Regex total timeout (default: 2.0)
* `--max-bytes <n>` – Max bytes to download (default: 5,000,000)
* `--max-matches <n>` – Cap number of returned matches (default: 1000)
* `--allow-private` – Permit private/loopback hosts (default: **blocked**)
* `--json` – Emit machine-readable JSON

---

## Output

### Human-readable (default)

```
URL:          https://example.com
Pattern:      '(?i)example'
Matches:      2
Elapsed:      87 ms
Content size: 1256 bytes (charset=utf-8)

First matches:
 1. [123:130] 'Example'
 2. [456:463] 'example'
```

### JSON (`--json`) — schema

```json
{
  "url": "https://example.com",
  "pattern": "(?i)example",
  "count": 2,
  "matches": [
    { "start": 123, "end": 130, "match": "Example", "groups": [] },
    { "start": 456, "end": 463, "match": "example", "groups": [] }
  ],
  "elapsed_ms": 87,
  "content_length": 1256,
  "charset": "utf-8"
}
```

**Notes**

* `groups` lists captured groups (empty strings for unmatched optional groups).
* `elapsed_ms` covers fetch + regex search.

---

## Programmatic use

```python
from url_regex_scanner import scan_url

result = scan_url(
    "https://example.com",
    r"(?i)example",
    http_timeout_s=8.0,
    regex_timeout_s=1.5,
    max_bytes=2_000_000,
    ignore_case=True,
)
print(result.count)
for m in result.matches:
    print(m.start, m.end, m.match)
```

---

## Exit codes

| Code | Meaning                                                         |
| ---: | --------------------------------------------------------------- |
|    0 | Success                                                         |
|    1 | Unexpected error (generic fallback)                             |
|    2 | Invalid input / unsupported scheme / invalid regex / SSRF block |
|    3 | Network/HTTP error, size limit exceeded, or timeout triggered   |

---

## Security considerations

* **SSRF mitigation:** By default, the tool resolves the host and **refuses** connections to private, loopback, link-local, multicast, and reserved ranges. Use `--allow-private` only when you are certain it’s safe.
* **Content-Type allow-list:** Only textual types are processed. This avoids accidentally scanning binary payloads.
* **Resource limits:** `--max-bytes`, `--http-timeout`, and `--re-timeout` prevent excessive resource usage and hangs.
* **Regex safety:** The search runs in a separate thread with a hard timeout; still write patterns defensively to avoid catastrophic backtracking.
* **No JS execution:** The tool fetches raw responses only; it does not execute JavaScript or render pages.

---

## Limitations

* No headless browser; dynamic content loaded by JS will not be present.
* Regex timeout covers the **whole** search run, not per-match slices.
* Charset detection is header-based; if the server lies, decoding falls back to UTF-8 with replacement.
* Only basic compression (`gzip`/`deflate`) is supported.

---

## Development

### Code style & typing

```bash
mypy url_regex_scanner.py
ruff check url_regex_scanner.py
python -m pytest -q  # if you add tests
```

Suggested `mypy` options (e.g. in `mypy.ini`):

```ini
[mypy]
python_version = 3.8
warn_unused_ignores = True
warn_return_any = True
warn_redundant_casts = True
disallow_untyped_defs = True
no_implicit_optional = True
strict_optional = True
```

### Minimal test sketch

```python
# tests/test_scanner.py
from url_regex_scanner import scan_url

def test_example_com():
    r = scan_url("https://example.com", r"(?i)\bexample\b")
    assert r.count >= 1
```

---

## FAQ

**Why not `requests`?**
To keep dependencies to zero and make auditing easier. The stdlib is sufficient for this use-case.

**Can I scan binary files?**
No. The scanner intentionally refuses non-textual Content-Types.

**Can this bypass corporate proxies or CORS?**
No. It makes direct HTTP(S) requests from where it runs.

---

## Licence

MIT

---

## Responsible use

Only scan systems you own or are authorised to test. Respect laws, Terms of Service, and privacy.

