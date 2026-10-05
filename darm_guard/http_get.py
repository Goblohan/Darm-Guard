"""Governed GET: the network side of the http_get tool.

Everything here is decided before, or happens after, the kernel's decision; this
module never decides whether a call is allowed. It provides:

- normal_url: a URL is accepted only if it is already in normal form (https,
  lowercase host, no credentials, no default port, no dot segments, no fragment,
  percent-encoding only where needed). Like the path normal form, a URL is never
  repaired, only refused, so a policy prefix compares what will actually be fetched.
- address checks: loopback, private, link-local (cloud metadata), multicast and
  reserved addresses are refused unless the principal allows them by name, and
  every address the name resolves to must pass.
- fetch: connects to the checked address itself, so a second DNS answer cannot
  change it, verifies TLS for the host, attaches the principal's credential,
  never follows a redirect, bounds the body and the time, and records the server's
  certificate. Outcomes: failed (nothing was sent), succeeded (a response arrived),
  unknown (sent, but no complete answer: what the remote did is unknowable, E31).
- A credential the remote echoes back is withheld from what the agent receives.
"""
import hashlib, http.client, ipaddress, re, socket, ssl, urllib.parse

MAX_BODY = 1 << 20          # bytes returned to the agent; the rest is reported as truncated
TIMEOUT = 10.0              # seconds, for connecting and for each read
MAX_URL = 2048
_UNRESERVED = re.compile(r"[A-Za-z0-9\-._~]")
_PATH_CHARS = re.compile(r"^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-F]{2})*$")
_QUERY_CHARS = re.compile(r"^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-F]{2})*$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4 = re.compile(r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
_NUMERIC_HOST = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$")
WITHHELD = "[credential withheld]"


def _pct_ok(s: str) -> bool:
    """Percent-encoding only where needed: never of an unreserved character, a slash,
    a backslash or a dot, which would let one URL be spelled two ways."""
    for m in re.finditer(r"%([0-9A-Fa-f]{2})", s):
        h = m.group(1)
        if h != h.upper():
            return False
        ch = chr(int(h, 16))
        if _UNRESERVED.match(ch) or ch in "/\\.":
            return False
    return True


def normal_url(url) -> bool:
    """True iff url is a governed-GET URL in normal form, exactly as given."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL or not url.isascii():
        return False
    if any(c.isspace() or ord(c) < 0x21 or ord(c) == 0x7f for c in url) or "\\" in url or "#" in url:
        return False
    if not url.startswith("https://"):
        return False
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        return False
    netloc = p.netloc
    if "@" in netloc or not p.hostname or netloc.startswith("["):
        return False                       # no credentials in the URL; no IPv6 literals in v1
    host, _, port_s = netloc.partition(":")
    if host != p.hostname:                 # urlsplit lowercases; the given host must already be lowercase
        return False
    if port_s:
        if not port_s.isdigit() or port_s.startswith("0") or port in (None, 443) or not 0 < port < 65536:
            return False
    if not _IPV4.match(host):
        # a numeric-looking host that is not a canonical IPv4 address (0177.0.0.1, 0x7f.0.0.1,
        # 2130706433, 127.1) is read as an address by resolvers: a second spelling, so refused
        if _NUMERIC_HOST.match(host) or host.rsplit(".", 1)[-1].isdigit():
            return False
        if host.endswith(".") or len(host) > 253 or "." not in host and host != "localhost":
            return False
        if not all(_LABEL.match(label) for label in host.split(".")):
            return False
    path, query = p.path, p.query
    if not path.startswith("/") or "//" in path:
        return False
    if any(seg in (".", "..") for seg in path.split("/")):
        return False
    if not _PATH_CHARS.match(path) or not _pct_ok(path):
        return False
    if "?" in url and not query:
        return False                       # a bare '?' is a second spelling of the same URL
    if query and (not _QUERY_CHARS.match(query) or not _pct_ok(query)):
        return False
    return url == urllib.parse.urlunsplit(("https", netloc, path, query, ""))


def address_refused(ip: str, host: str, allow_private) -> str:
    """Why this resolved address is refused, or '' if it may be contacted."""
    allow = set(allow_private or ())
    if host in allow or ip in allow:
        return ""
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    for attr, why in (("is_loopback", "loopback"), ("is_link_local", "link-local (includes cloud metadata)"),
                      ("is_private", "private"), ("is_multicast", "multicast"),
                      ("is_reserved", "reserved"), ("is_unspecified", "unspecified")):
        if getattr(a, attr):
            return f"{ip} is a {why} address, not allowed by the principal"
    return ""


def credential_for(url: str, credentials) -> tuple:
    """The principal's credential for the longest matching URL prefix: (header, value) or None.
    The value is read from its file at the time of the call and never returned to the agent."""
    best = None
    for c in credentials or ():
        if url.startswith(c["prefix"]) and (best is None or len(c["prefix"]) > len(best["prefix"])):
            best = c
    if best is None:
        return None
    with open(best["value_file"]) as f:
        return best["header"], f.read().strip()


def fetch(url: str, *, credentials=None, allow_private=None, resolver=socket.getaddrinfo,
          timeout: float = TIMEOUT, max_body: int = MAX_BODY, cafile=None) -> dict:
    """GET url, which must already be decided and in normal form. Never raises."""
    out = {"outcome": "failed", "url": url}
    if not normal_url(url):
        return dict(out, error="url not in normal form")
    p = urllib.parse.urlsplit(url)
    host, port = p.hostname, p.port or 443
    target = p.path + ("?" + p.query if p.query else "")
    try:
        infos = resolver(host, port, proto=socket.IPPROTO_TCP)
        addrs = sorted({i[4][0] for i in infos})
    except (OSError, UnicodeError) as e:
        return dict(out, error=f"name not resolved: {e}")
    if not addrs:
        return dict(out, error="name not resolved")
    for ip in addrs:                       # every answer must pass, not just the first
        why = address_refused(ip, host, allow_private)
        if why:
            return dict(out, error=why)
    cred = None
    try:
        cred = credential_for(url, credentials)
    except OSError as e:
        return dict(out, error=f"credential unavailable: {e}")
    ip = addrs[0]
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        ctx = ssl.create_default_context(cafile=cafile)
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except (OSError, ssl.SSLError) as e:
        return dict(out, error=f"no connection: {e}")
    server = {"address": ip, "cert_sha256": hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()}
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = tls
    sent = False
    try:
        conn.putrequest("GET", target, skip_accept_encoding=True)
        conn.putheader("Accept-Encoding", "identity")
        conn.putheader("User-Agent", "darm-guard")
        conn.putheader("Connection", "close")
        if cred:
            conn.putheader(cred[0], cred[1])
        conn.endheaders()
        sent = True
        resp = conn.getresponse()
        body = resp.read(max_body + 1)
        truncated = len(body) > max_body
        body = body[:max_body]
        text = body.decode("utf-8", errors="replace")
        if cred and cred[1] and cred[1] in text:
            text = text.replace(cred[1], WITHHELD)   # an echoed credential never reaches the agent
        result = dict(out, outcome="succeeded", status=resp.status,
                      content_type=resp.getheader("Content-Type", ""),
                      body=text, body_sha256=hashlib.sha256(body).hexdigest(),
                      truncated=truncated, server=server)
        if 300 <= resp.status < 400:
            result["location"] = resp.getheader("Location", "")
            result["redirect"] = "not followed; propose the location as a new request to fetch it"
        return result
    except Exception as e:
        if not sent:
            return dict(out, error=f"not sent: {e}", server=server)
        return dict(out, outcome="unknown", server=server,
                    error=f"sent, but no complete answer ({type(e).__name__}): what the remote did is unknown")
    finally:
        try:
            conn.close()
        except Exception:
            pass
