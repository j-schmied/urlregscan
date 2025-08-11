#!/usr/bin/env python3
"""
URL Regex Scanner – secure tool to scan a search a url using regex

Author: Jannik Schmied, 2025
Version: 1.0
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import asdict, dataclass
from typing import Final, Iterable, List, Mapping, Optional, Sequence, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

# --------- Configuration ---------
USER_AGENT: Final[str] = "URLRegexScanner/1.0 (+https://localhost) Python-urllib"
ALLOWED_SCHEMES: Final[Tuple[str, ...]] = ("http", "https")
ALLOWED_CONTENT_TYPES_PREFIX: Final[Tuple[str, ...]] = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
)
DEFAULT_HTTP_TIMEOUT_S: Final[float] = 10.0
DEFAULT_MAX_BYTES: Final[int] = 5_000_000  # 5 MB
DEFAULT_MAX_MATCHES: Final[int] = 1000
DEFAULT_REGEX_TIMEOUT_S: Final[float] = 2.0  # Overall restriction for the entire scan 

FLAGS_MAP: Final[Mapping[str, int]] = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "x": re.VERBOSE,
}


# --------- Data models ---------
@dataclass(frozen=True)
class MatchResult:
    start: int
    end: int
    match: str
    groups: Tuple[str, ...]


@dataclass(frozen=True)
class ScanResult:
    url: str
    pattern: str
    count: int
    matches: List[MatchResult]
    elapsed_ms: int
    content_length: int
    charset: str


# --------- Helper functions ---------
def validate_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}. Only http/https are allowed.")
    if not parsed.netloc:
        raise ValueError("Invalid URL: missing host.")
    return parsed


def host_is_private_or_loopback(hostname: str) -> bool:
    """Check resolved target IP(s) to prevent off-target (SSRF) to private/loopback areas."""
    try:
        infos = socket.getaddrinfo(hostname, None)  # type: ignore[no-untyped-call]
    except socket.gaierror:
        # DNS resolution failed – not private, but call will fail later 
        return False

    for family, _, _, _, sockaddr in infos:
        ip_str: Optional[str] = None
        if family == socket.AF_INET:
            ip_str = sockaddr[0]
        elif family == socket.AF_INET6:
            ip_str = sockaddr[0]
        if not ip_str:
            continue
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def _decompress_if_needed(raw: bytes, content_encoding: Optional[str]) -> bytes:
    if not content_encoding:
        return raw
    enc = content_encoding.lower().strip()
    if enc == "gzip":
        # gzip wrapper
        return zlib.decompress(raw, zlib.MAX_WBITS | 16)
    if enc == "deflate":
        # zlib or raw deflate – try zlib header, raw else
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    # unknown -> unchanged
    return raw


def fetch_text(
    url: str,
    *,
    timeout_s: float = DEFAULT_HTTP_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_BYTES,
    forbid_private_hosts: bool = True,
) -> Tuple[str, int, str]:
    """
    Retrieves the URL, validates content type, limits size, decodes text.

    Returns: (text, content_length, charset)
    """
    parsed = validate_url(url)

    if forbid_private_hosts and host_is_private_or_loopback(parsed.hostname or ""):
        raise PermissionError("Refusing to connect to private/loopback address.")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # type: ignore[no-untyped-call]
            # Validate Content-Type
            ctype_full = resp.headers.get("Content-Type", "")
            ctype = ctype_full.split(";", 1)[0].strip().lower()

            if not any(ctype.startswith(pref) for pref in ALLOWED_CONTENT_TYPES_PREFIX):
                raise ValueError(f"Unsupported Content-Type: {ctype_full!r}")

            # Limit bytes
            chunk_size = 64 * 1024
            remaining = max_bytes
            chunks: List[bytes] = []
            while remaining > 0:
                chunk = resp.read(min(chunk_size, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining <= 0 and resp.read(1):
                raise MemoryError(f"Response exceeds max_bytes={max_bytes} limit.")

            raw = b"".join(chunks)

            # Decompress (gzip/deflate)
            raw = _decompress_if_needed(raw, resp.headers.get("Content-Encoding"))

            # Determine charset
            charset = "utf-8"

            # From HTTP-Header
            if "charset=" in ctype_full.lower():
                try:
                    charset = ctype_full.lower().split("charset=", 1)[1].split(";")[0].strip()
                except Exception:
                    pass

            try:
                text = raw.decode(charset, errors="replace")
            except LookupError:
                # Unknown charset -> UTF-8 Fallback
                charset = "utf-8"
                text = raw.decode("utf-8", errors="replace")

            text = text.replace("\r\n", "\n").replace("\r", "\n")

            return text, len(raw), charset
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"HTTP error {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise ConnectionError(f"URL error: {e.reason}") from e


def parse_flags(ignore_case: bool, multiline: bool, dotall: bool, verbose: bool) -> int:
    flags = 0
    if ignore_case:
        flags |= re.IGNORECASE
    if multiline:
        flags |= re.MULTILINE
    if dotall:
        flags |= re.DOTALL
    if verbose:
        flags |= re.VERBOSE
    return flags


def _regex_worker(
    text: str, pattern: str, flags: int, max_matches: int
) -> List[MatchResult]:
    regex = re.compile(pattern, flags)
    results: List[MatchResult] = []

    for m in regex.finditer(text):
        groups: Tuple[str, ...] = tuple(g if g is not None else "" for g in m.groups())
        results.append(
            MatchResult(start=m.start(), end=m.end(), match=m.group(0), groups=groups)
        )
        if len(results) >= max_matches:
            break
    return results


def run_regex_with_timeout(
    text: str,
    pattern: str,
    *,
    flags: int,
    timeout_s: float,
    max_matches: int,
) -> List[MatchResult]:
    """
    Runs the regex in a separate thread to enforce a hard timeout for 
    potentially “catastrophic” regexes.
    """
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_regex_worker, text, pattern, flags, max_matches)
        try:
            return fut.result(timeout=timeout_s)
        except FuturesTimeoutError as e:
            raise TimeoutError(
                f"Regex processing exceeded timeout of {timeout_s:.2f}s"
            ) from e


def scan_url(
    url: str,
    pattern: str,
    *,
    http_timeout_s: float = DEFAULT_HTTP_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_BYTES,
    regex_timeout_s: float = DEFAULT_REGEX_TIMEOUT_S,
    max_matches: int = DEFAULT_MAX_MATCHES,
    ignore_case: bool = False,
    multiline: bool = False,
    dotall: bool = False,
    verbose: bool = False,
    forbid_private_hosts: bool = True,
) -> ScanResult:
    start = time.perf_counter()
    text, content_len, charset = fetch_text(
        url,
        timeout_s=http_timeout_s,
        max_bytes=max_bytes,
        forbid_private_hosts=forbid_private_hosts,
    )

    flags = parse_flags(ignore_case, multiline, dotall, verbose)
    try:
        matches = run_regex_with_timeout(
            text, pattern, flags=flags, timeout_s=regex_timeout_s, max_matches=max_matches
        )
    except re.error as e:
        raise ValueError(f"Invalid regular expression: {e}") from e

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return ScanResult(
        url=url,
        pattern=pattern,
        count=len(matches),
        matches=matches,
        elapsed_ms=elapsed_ms,
        content_length=content_len,
        charset=charset,
    )


# --------- CLI ---------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Fetch a URL and search its textual content with a regular expression."
    )
    p.add_argument("url", help="Target URL (http/https).")
    p.add_argument("pattern", help="Regular expression pattern.")
    p.add_argument("-i", "--ignore-case", action="store_true", help="Regex IGNORECASE.")
    p.add_argument("-m", "--multiline", action="store_true", help="Regex MULTILINE.")
    p.add_argument("-s", "--dotall", action="store_true", help="Regex DOTALL ('.' matches newline).")
    p.add_argument("-x", "--verbose", action="store_true", help="Regex VERBOSE (extended).")
    p.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT_S, help="HTTP timeout (s).")
    p.add_argument("--re-timeout", type=float, default=DEFAULT_REGEX_TIMEOUT_S, help="Regex total timeout (s).")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Max bytes to download.")
    p.add_argument("--max-matches", type=int, default=DEFAULT_MAX_MATCHES, help="Max matches to return.")
    p.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow connections to private/loopback hosts (disabled by default).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output JSON (machine-readable). If not set, prints a readable summary.",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        result = scan_url(
            args.url,
            args.pattern,
            http_timeout_s=args.http_timeout,
            max_bytes=args.max_bytes,
            regex_timeout_s=args.re_timeout,
            max_matches=args.max_matches,
            ignore_case=args.ignore_case,
            multiline=args.multiline,
            dotall=args.dotall,
            verbose=args.verbose,
            forbid_private_hosts=not args.allow_private,
        )
    except (ValueError, PermissionError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except (ConnectionError, MemoryError, TimeoutError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}", file=sys.stderr)
        return 1

    if args.json:
        payload = asdict(result)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"URL:          {result.url}")
        print(f"Pattern:      {result.pattern!r}")
        print(f"Matches:      {result.count}")
        print(f"Elapsed:      {result.elapsed_ms} ms")
        print(f"Content size: {result.content_length} bytes (charset={result.charset})")
        if result.matches:
            print("\nFirst matches:")
            for i, m in enumerate(result.matches[:10], 1):
                snippet = m.match
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                print(f"{i:>2}. [{m.start}:{m.end}] {snippet!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

