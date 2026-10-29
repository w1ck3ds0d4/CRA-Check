"""Bounded, https-only URL fetching for user-supplied document URLs.

Rules: https only, port 443 only, no credentials in the URL, the host must resolve
to public addresses only, redirects are followed (at most 3) only when every hop
passes the same checks, and the body is capped in size and in total read time.
"""

import ipaddress
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 15
TOTAL_SECONDS = 30
USER_AGENT = "cra-gap-check-apify-actor/0.1"


class FetchError(Exception):
    """A URL was refused or could not be fetched. The message is safe to show."""


def _resolve(host):
    """Return the IP address strings a host resolves to (patched in tests)."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise FetchError(f"Could not resolve host {host}.") from None
    return sorted({info[4][0] for info in infos})


def _is_public(addr):
    ip = ipaddress.ip_address(addr)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_global


def check_url(url):
    """Validate a URL against the fetch rules and return it unchanged."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise FetchError("URL is empty or too long.")
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise FetchError("URL contains whitespace or control characters.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise FetchError("URL is not valid.") from None
    if parts.scheme.lower() != "https":
        raise FetchError("Only https URLs are allowed.")
    host = parts.hostname
    if not host:
        raise FetchError("URL has no host.")
    if parts.username is not None or parts.password is not None:
        raise FetchError("URLs with embedded credentials are not allowed.")
    if port not in (None, 443):
        raise FetchError("Only the default https port (443) is allowed.")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        addrs = _resolve(host)
    if not addrs:
        raise FetchError(f"Could not resolve host {host}.")
    for addr in addrs:
        if not _is_public(addr):
            raise FetchError(f"Host {host} does not resolve to a public address.")
    return url


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            check_url(newurl)
        except FetchError as exc:
            raise FetchError(f"Redirect refused: {exc}") from None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener():
    # Only https: no http, ftp, file or data handlers, and no environment proxies.
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler({}),
        urllib.request.UnknownHandler(),
        urllib.request.HTTPSHandler(),
        _CheckedRedirects(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def fetch_bytes(url, max_bytes):
    """GET an https URL and return its body, refusing anything over max_bytes."""
    check_url(url)
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, text/markdown, */*;q=0.1",
    })
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        with _build_opener().open(req, timeout=TIMEOUT_SECONDS) as resp:
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"Document is larger than the {max_bytes // 1024} KiB limit.")
            chunks, total = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise FetchError("Download took too long.")
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"Document is larger than the {max_bytes // 1024} KiB limit.")
                chunks.append(chunk)
    except FetchError:
        raise
    except urllib.error.HTTPError as exc:
        raise FetchError(f"The server answered HTTP {exc.code}.") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise FetchError("The document could not be downloaded.") from None
    return b"".join(chunks)
