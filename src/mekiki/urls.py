"""URL and domain handling shared by every rule.

All of axis 4 ultimately asks "which site is this really?", so the parsing
lives in one place and is tested on its own. Nothing here touches the network:
a URL is only ever looked at as text.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit

NON_WEB_SCHEMES: frozenset[str] = frozenset(
    {"mailto", "tel", "sms", "javascript", "data", "file", "about", "chrome"}
)
"""Schemes that have no host to compare. ``javascript:`` and ``data:`` are
interesting for other reasons, but they are not domains."""


MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        # Japan, the main target of this tool.
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "lg.jp",
        "ed.jp",
        "gr.jp",
        "ad.jp",
        # A few others that show up in international phishing.
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.kr",
        "or.kr",
        "com.cn",
        "net.cn",
        "org.cn",
        "com.tw",
        "com.hk",
        "com.sg",
        "co.th",
        "co.in",
        "co.nz",
        "com.br",
    }
)
"""Public suffixes made of two labels.

This is a deliberately small, hand kept subset of the Public Suffix List. The
full list is a 15000 line file that needs updating, and getting ``co.jp``
right already covers the Japanese senders this tool is about. Known limitation:
Japanese geographic domains (``city.sapporo.jp``) are not handled.
"""


REDIRECT_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "u",
        "uri",
        "redirect",
        "redirect_uri",
        "redirect_url",
        "redir",
        "next",
        "return",
        "returnurl",
        "return_url",
        "continue",
        "dest",
        "destination",
        "goto",
        "target",
        "link",
        "out",
        "to",
        "r",
    }
)
"""Query parameters that a redirector uses for its destination.

Restricting the open redirect rule to these names is what keeps it from firing
on an ordinary search box (``?q=https://...``)."""


def extract_host(url: str | None) -> str | None:
    """Host of a URL, lower cased, without port or user info.

    Returns ``None`` when there is no host to speak of: a relative link, an
    empty string, or a non web scheme such as ``mailto:``.
    """
    if not url:
        return None
    candidate = url.strip()
    if not candidate:
        return None

    # A relative reference has no host, and must not be guessed at.
    if candidate[0] in "/?#" and not candidate.startswith("//"):
        return None

    scheme, separator, _ = candidate.partition(":")
    if separator and scheme.lower() in NON_WEB_SCHEMES:
        return None

    if "://" not in candidate:
        # urlsplit reads a bare "sakura-bank.example/x" as a path, so give it
        # a scheme. This also covers protocol relative "//host/x".
        candidate = "http://" + candidate.lstrip("/")

    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        # Malformed authority, e.g. an unclosed IPv6 bracket.
        return None
    if not host:
        return None
    # A trailing dot is a valid fully qualified name but breaks comparisons.
    host = host.strip(".")
    return host or None


def is_ip_host(host: str | None) -> bool:
    """Whether the host is a bare IP address rather than a name."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Integer form, e.g. http://3232235777/ for 192.168.1.1.
    if host.isdigit():
        try:
            ipaddress.ip_address(int(host))
            return True
        except ValueError:
            return False
    return False


def registrable_domain(host: str | None) -> str | None:
    """The part of a host that someone had to register (roughly eTLD+1).

    ``mail.sakura-bank.example`` and ``sakura-bank.example`` share an owner, so
    comparing whole hosts would report a mismatch where there is none.
    """
    if not host:
        return None
    normalized = host.strip().strip(".").lower()
    if not normalized:
        return None
    if is_ip_host(normalized):
        return normalized

    labels = normalized.split(".")
    if len(labels) < 2:
        return normalized
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        if len(labels) < 3:
            return normalized
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def registrable_domain_of_url(url: str | None) -> str | None:
    """Convenience wrapper: host extraction followed by eTLD+1."""
    return registrable_domain(extract_host(url))


def same_registrable_domain(left: str | None, right: str | None) -> bool:
    """Whether two hosts belong to the same registered domain.

    Unknown hosts are never treated as equal; "we could not tell" must not
    become "it matches".
    """
    left_domain = registrable_domain(left)
    right_domain = registrable_domain(right)
    if left_domain is None or right_domain is None:
        return False
    return left_domain == right_domain


def is_subdomain_of(host: str | None, domain: str | None) -> bool:
    """Whether ``host`` is ``domain`` itself or a name below it."""
    if not host or not domain:
        return False
    host_normalized = host.strip().strip(".").lower()
    domain_normalized = domain.strip().strip(".").lower()
    if not host_normalized or not domain_normalized:
        return False
    return host_normalized == domain_normalized or host_normalized.endswith(
        "." + domain_normalized
    )


def email_address_domain(address: str | None) -> str | None:
    """Domain part of an email address, lower cased."""
    if not address or "@" not in address:
        return None
    domain = address.rpartition("@")[2].strip().strip(".").lower()
    return domain or None


def extract_redirect_urls(url: str | None) -> list[tuple[str, str]]:
    """Absolute URLs carried in redirect style query parameters.

    Returns ``(parameter name, embedded url)`` pairs. Only the parameter names
    in :data:`REDIRECT_PARAM_NAMES` are considered.
    """
    if not url:
        return []
    candidate = url.strip()
    if "://" not in candidate and not candidate.startswith("//"):
        candidate = "http://" + candidate.lstrip("/")
    try:
        query = urlsplit(candidate).query
    except ValueError:
        return []

    embedded: list[tuple[str, str]] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if name.lower() not in REDIRECT_PARAM_NAMES:
            continue
        # parse_qsl decodes once; decode again for double encoded payloads.
        decoded = unquote(value).strip()
        if decoded.lower().startswith(("http://", "https://")):
            embedded.append((name, decoded))
    return embedded


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'()）」】]+", re.IGNORECASE)

_EMAIL_IN_TEXT = re.compile(r"[^\s<>\"'()]+@[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", re.IGNORECASE)

_DOMAIN_IN_TEXT = re.compile(
    r"(?<![\w.-])"
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
    r"(?![\w-])",
    re.IGNORECASE,
)

_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "svg",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "csv",
        "txt",
        "zip",
        "exe",
        "html",
        "htm",
        "php",
        "aspx",
        "js",
        "css",
        "mp4",
    }
)
"""Last labels that make a dotted token a file name rather than a host.

Without this, text such as "campaign.png" would be read as a domain.
"""


def _looks_like_a_host(token: str) -> bool:
    """Whether a dotted token is plausibly a host name."""
    last_label = token.rsplit(".", 1)[-1].lower()
    if last_label in _FILE_EXTENSIONS:
        return False
    # A public suffix is alphabetic and at least two characters ("jp", "com").
    return len(last_label) >= 2 and last_label.isalpha()


def host_claimed_in_text(
    text: str | None, *, include_email_addresses: bool = False
) -> str | None:
    """The host a piece of human readable text claims, if it names one.

    Used for link text ("sakura-bank.example" written over a link to
    somewhere else) and for sender display names.

    ``include_email_addresses`` changes what an address means. In link text,
    ``support@sakura-bank.example`` is contact information and says nothing
    about where the link goes, so addresses are ignored. In a display name it
    is a claim about who is writing, so the caller asks for them.
    """
    if not text:
        return None

    url_match = _URL_IN_TEXT.search(text)
    if url_match:
        return extract_host(url_match.group(0))

    address_match = _EMAIL_IN_TEXT.search(text)
    if include_email_addresses and address_match:
        return email_address_domain(address_match.group(0))

    # Strip addresses so their domain is not picked up as a bare domain.
    without_addresses = _EMAIL_IN_TEXT.sub(" ", text)
    for candidate in _DOMAIN_IN_TEXT.finditer(without_addresses):
        token = candidate.group(0)
        if _looks_like_a_host(token):
            return extract_host(token)
    return None


def is_punycode(host: str | None) -> bool:
    """Whether any label of the host is punycode (an encoded IDN)."""
    if not host:
        return False
    return any(label.startswith("xn--") for label in host.lower().split("."))


def decode_punycode(host: str) -> str:
    """Best effort conversion of a punycode host back to Unicode.

    Punycode on its own is not suspicious; a punycode host that *looks like* a
    known brand is. Comparing them requires the decoded form. If the host
    cannot be decoded it is returned unchanged, so callers never have to deal
    with an exception.
    """
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host
