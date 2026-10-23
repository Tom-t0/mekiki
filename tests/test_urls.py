"""Tests for URL and domain handling.

Every rule in axis 4 stands on these functions, so they are tested on their
own rather than only through the rules.
"""

from __future__ import annotations

import pytest

from mekiki.urls import (
    decode_punycode,
    email_address_domain,
    extract_host,
    extract_redirect_urls,
    is_ip_host,
    is_punycode,
    is_subdomain_of,
    registrable_domain,
    registrable_domain_of_url,
    same_registrable_domain,
)

# --------------------------------------------------------------------------
# extract_host
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://sakura-bank.example/login", "sakura-bank.example"),
        ("http://sakura-bank.example", "sakura-bank.example"),
        # Case and port are not part of the identity of a host.
        ("https://SAKURA-BANK.Example:8443/x", "sakura-bank.example"),
        # User info before @ is a classic way to hide the real host.
        ("https://sakura-bank.example@evil.example/login", "evil.example"),
        # A trailing dot is valid but would break string comparison.
        ("https://sakura-bank.example./", "sakura-bank.example"),
        # No scheme at all, as often written in anchor text.
        ("sakura-bank.example/login", "sakura-bank.example"),
        ("www.sakura-bank.example", "www.sakura-bank.example"),
        # Protocol relative.
        ("//sakura-bank.example/x", "sakura-bank.example"),
        # IPv6 comes back without the brackets.
        ("http://[2001:db8::1]:8080/x", "2001:db8::1"),
        ("  https://sakura-bank.example/x  ", "sakura-bank.example"),
    ],
)
def test_extract_host(url: str, expected: str) -> None:
    assert extract_host(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "   ",
        # Non web schemes have no host to compare.
        "mailto:support@sakura-bank.example",
        "tel:0120-000-000",
        "javascript:void(0)",
        "data:text/html;base64,PHA+",
        # Relative references.
        "/login",
        "?next=1",
        "#section",
        # Malformed authority.
        "http://[not-closed",
    ],
)
def test_extract_host_returns_none(url: str | None) -> None:
    assert extract_host(url) is None


# --------------------------------------------------------------------------
# is_ip_host
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["192.0.2.10", "127.0.0.1", "2001:db8::1", "3232235777"],
)
def test_ip_hosts(host: str) -> None:
    assert is_ip_host(host) is True


@pytest.mark.parametrize(
    "host",
    [None, "", "sakura-bank.example", "192.0.2.10.example", "999.999.999.999", "1.2.3"],
)
def test_non_ip_hosts(host: str | None) -> None:
    assert is_ip_host(host) is False


# --------------------------------------------------------------------------
# registrable_domain
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("sakura-bank.example", "sakura-bank.example"),
        ("mail.sakura-bank.example", "sakura-bank.example"),
        ("a.b.c.sakura-bank.example", "sakura-bank.example"),
        # Two label public suffixes must not be split.
        ("sakura-bank.co.jp", "sakura-bank.co.jp"),
        ("mail.sakura-bank.co.jp", "sakura-bank.co.jp"),
        ("city.example.lg.jp", "example.lg.jp"),
        ("shop.example.com.au", "example.com.au"),
        # A bare public suffix is returned as is; there is nothing above it.
        ("co.jp", "co.jp"),
        ("localhost", "localhost"),
        # IP addresses have no registrable domain, so they stand for themselves.
        ("192.0.2.10", "192.0.2.10"),
        ("Mail.SAKURA-BANK.Example.", "sakura-bank.example"),
        (None, None),
        ("", None),
    ],
)
def test_registrable_domain(host: str | None, expected: str | None) -> None:
    assert registrable_domain(host) == expected


def test_registrable_domain_of_url() -> None:
    assert (
        registrable_domain_of_url("https://mail.sakura-bank.example/x")
        == "sakura-bank.example"
    )
    assert registrable_domain_of_url("mailto:a@sakura-bank.example") is None


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("mail.sakura-bank.example", "sakura-bank.example", True),
        ("sakura-bank.example", "sakura-bamk.example", False),
        # A subdomain of someone else's domain is not a match.
        ("sakura-bank.example.evil.example", "sakura-bank.example", False),
        # Unknown must never read as "matches".
        (None, "sakura-bank.example", False),
        ("sakura-bank.example", None, False),
        (None, None, False),
    ],
)
def test_same_registrable_domain(
    left: str | None, right: str | None, expected: bool
) -> None:
    assert same_registrable_domain(left, right) is expected


@pytest.mark.parametrize(
    ("host", "domain", "expected"),
    [
        ("sakura-bank.example", "sakura-bank.example", True),
        ("mail.sakura-bank.example", "sakura-bank.example", True),
        # Suffix matching without the dot would accept this.
        ("evilsakura-bank.example", "sakura-bank.example", False),
        ("sakura-bank.example.evil.example", "sakura-bank.example", False),
        (None, "sakura-bank.example", False),
        ("sakura-bank.example", None, False),
    ],
)
def test_is_subdomain_of(host: str | None, domain: str | None, expected: bool) -> None:
    assert is_subdomain_of(host, domain) is expected


# --------------------------------------------------------------------------
# email_address_domain
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("info@sakura-bank.example", "sakura-bank.example"),
        ("info@MAIL.Sakura-Bank.Example", "mail.sakura-bank.example"),
        ("odd@part@sakura-bank.example", "sakura-bank.example"),
        ("not-an-address", None),
        ("info@", None),
        (None, None),
    ],
)
def test_email_address_domain(address: str | None, expected: str | None) -> None:
    assert email_address_domain(address) == expected


# --------------------------------------------------------------------------
# extract_redirect_urls
# --------------------------------------------------------------------------


def test_redirect_parameter_is_found() -> None:
    url = "https://link.example/r?url=https%3A%2F%2Fevil.example%2Flogin"
    assert extract_redirect_urls(url) == [("url", "https://evil.example/login")]


def test_several_redirect_parameters_are_found() -> None:
    url = "https://link.example/r?next=https://a.example&dest=https://b.example"
    assert extract_redirect_urls(url) == [
        ("next", "https://a.example"),
        ("dest", "https://b.example"),
    ]


def test_double_encoded_redirect_is_decoded() -> None:
    url = "https://link.example/r?u=https%253A%252F%252Fevil.example%252Fx"
    assert extract_redirect_urls(url) == [("u", "https://evil.example/x")]


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "https://sakura-bank.example/login",
        # A search box that happens to contain a URL is not a redirector.
        "https://search.nijiiro-shop.example/?q=https://evil.example",
        # A redirect parameter without an absolute URL in it.
        "https://link.example/r?url=/local/path",
        "https://link.example/r?url=",
    ],
)
def test_no_redirect_parameter(url: str | None) -> None:
    assert extract_redirect_urls(url) == []


# --------------------------------------------------------------------------
# punycode
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("xn--eckwd4c7c.example", True),
        ("mail.xn--eckwd4c7c.example", True),
        ("sakura-bank.example", False),
        (None, False),
    ],
)
def test_is_punycode(host: str | None, expected: bool) -> None:
    assert is_punycode(host) is expected


def test_decode_punycode() -> None:
    assert decode_punycode("xn--eckwd4c7c.example") == "ドメイン.example"


def test_decode_punycode_leaves_undecodable_hosts_alone() -> None:
    assert decode_punycode("xn--not valid--.example") == "xn--not valid--.example"
