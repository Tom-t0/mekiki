"""Tests for the url_shortener rule."""

from __future__ import annotations

from collections.abc import Callable

from mekiki.email_input import EmailLink, NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import url_shortener
from mekiki.rules.base import RuleContext

MakeEmail = Callable[..., NormalizedEmail]
MakeLink = Callable[..., EmailLink]


def test_known_shortener_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("https://bit.ly/abc123")])
    findings = url_shortener.check(email, context)
    assert [finding.signal for finding in findings] == [SpoofSignal.URL_SHORTENER]
    assert "bit.ly" in findings[0].detail


def test_a_subdomain_of_a_shortener_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """Branded short links still run through the service."""
    email = make_email(links=[make_link("https://brand.bit.ly/abc123")])
    assert len(url_shortener.check(email, context)) == 1


def test_the_same_service_is_reported_once(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[make_link("https://bit.ly/aaa"), make_link("https://bit.ly/bbb")]
    )
    assert len(url_shortener.check(email, context)) == 1


def test_different_services_are_reported_separately(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[make_link("https://bit.ly/aaa"), make_link("https://tinyurl.com/bbb")]
    )
    assert len(url_shortener.check(email, context)) == 2


def test_the_list_is_taken_from_the_context(
    make_email: MakeEmail, make_link: MakeLink
) -> None:
    """A rule reads no files, so a test can supply its own list."""
    email = make_email(links=[make_link("https://short.example/x")])
    assert url_shortener.check(email, RuleContext(shorteners=frozenset())) == []
    assert (
        len(
            url_shortener.check(
                email, RuleContext(shorteners=frozenset({"short.example"}))
            )
        )
        == 1
    )


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


def test_legitimate_link_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="ニジイロ通販",
        sender_address="news@nijiiro-shop.example",
        links=[make_link("https://nijiiro-shop.example/sale", "セール会場へ")],
    )
    assert url_shortener.check(email, context) == []


def test_a_domain_that_merely_looks_short_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("https://bit.example/abc")])
    assert url_shortener.check(email, context) == []


def test_non_web_schemes_are_ignored(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("mailto:support@sakura-bank.example")])
    assert url_shortener.check(email, context) == []
