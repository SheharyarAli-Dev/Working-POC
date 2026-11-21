"""Refuse requests whose Host header is not this machine (DNS-rebinding defence for the local dashboard).

A web page can point its own domain at 127.0.0.1 and then read the dashboard as a same-origin site; the
browser still sends that domain as Host. Only 127.0.0.1, localhost and [::1] (any port) are accepted, plus
the hosts listed, comma-separated, in ASENT_ALLOWED_HOSTS (empty by default). Anything else, including a
missing or malformed Host, gets 400 on every HTTP and WebSocket request (Starlette's TrustedHostMiddleware).
"""
import re

from starlette.middleware.trustedhost import TrustedHostMiddleware

DEFAULT_HOSTS = ("127.0.0.1", "localhost", "[::1]")
SETTING = "ASENT_ALLOWED_HOSTS"
# A plain DNS name / IPv4 address, or a bracketed IPv6 literal. No wildcard, port, scheme, path or trailing dot.
_ENTRY = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)*|\[[0-9a-f]*:[0-9a-f:.]+\]")


def allowed_hosts(environ):
    """Default loopback hosts plus the validated, lower-cased entries of ASENT_ALLOWED_HOSTS."""
    hosts = list(DEFAULT_HOSTS)
    for raw in environ.get(SETTING, "").split(","):
        entry = raw.strip().lower()
        if not entry:
            continue
        if not _ENTRY.fullmatch(entry):
            raise ValueError(f"{SETTING}: {raw.strip()!r} is not a host name; list bare names or IP addresses "
                             "separated by commas (no '*', port, scheme or path; write IPv6 as [addr])")
        if entry not in hosts:
            hosts.append(entry)
    return hosts


def protect(app, environ):
    """Install the Host check as the outermost middleware of `app` (call after any other add_middleware)."""
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts(environ), www_redirect=False)
