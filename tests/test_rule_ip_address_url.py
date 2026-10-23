"""Tests for the ip_address_url rule."""

from __future__ import annotations

from collections.abc import Callable

from mekiki.email_input import EmailLink, NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import ip_address_url
from mekiki.rules.base import RuleContext

MakeEmail = Callable[..., NormalizedEmail]
MakeLink = Callable[..., EmailLink]


def test_ipv4_link_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("http://203.0.113.5/login")])
    findings = ip_address_url.check(email, context)
    assert [finding.signal for finding in findings] == [SpoofSignal.IP_ADDRESS_URL]
    assert findings[0].quote == "http://203.0.113.5/login"


def test_ipv6_link_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("http://[2001:db8::1]/login")])
    assert len(ip_address_url.check(email, context)) == 1


def test_integer_form_link_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """http://3232235777/ is another spelling of http://192.168.1.1/."""
    email = make_email(links=[make_link("http://3232235777/")])
    assert len(ip_address_url.check(email, context)) == 1


def test_the_same_host_is_reported_once(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("http://203.0.113.5/login"),
            make_link("http://203.0.113.5/help"),
        ]
    )
    findings = ip_address_url.check(email, context)
    assert len(findings) == 1
    assert findings[0].quote == "http://203.0.113.5/login"


def test_distinct_hosts_are_reported_separately(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[make_link("http://203.0.113.5/a"), make_link("http://198.51.100.9/b")]
    )
    assert len(ip_address_url.check(email, context)) == 2


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


def test_legitimate_bank_notice_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="info@sakura-bank.example",
        body_text="ご利用明細をご確認ください。",
        links=[make_link("https://sakura-bank.example/statement", "ご利用明細")],
    )
    assert ip_address_url.check(email, context) == []


def test_a_domain_that_merely_contains_digits_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("https://192-0-2-10.example/login")])
    assert ip_address_url.check(email, context) == []


def test_non_web_schemes_are_ignored(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("mailto:support@sakura-bank.example"),
            make_link("tel:0120-000-000"),
        ]
    )
    assert ip_address_url.check(email, context) == []


def test_an_email_without_links_is_not_reported(
    make_email: MakeEmail, context: RuleContext
) -> None:
    assert ip_address_url.check(make_email(body_text="本文のみ"), context) == []
