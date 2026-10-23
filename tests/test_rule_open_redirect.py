"""Tests for the open_redirect rule."""

from __future__ import annotations

from collections.abc import Callable

from mekiki.email_input import EmailLink, NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import open_redirect
from mekiki.rules.base import RuleContext

MakeEmail = Callable[..., NormalizedEmail]
MakeLink = Callable[..., EmailLink]


# --------------------------------------------------------------------------
# Must fire
# --------------------------------------------------------------------------


def test_redirect_to_another_site_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link(
                "https://trusted.example/r?url=https%3A%2F%2Fevil.example%2Flogin",
                "ご確認はこちら",
            )
        ]
    )
    findings = open_redirect.check(email, context)
    assert [finding.signal for finding in findings] == [SpoofSignal.OPEN_REDIRECT]
    assert "evil.example" in findings[0].detail


def test_redirect_from_a_listed_organization_to_elsewhere_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """A legitimate domain being used as the stepping stone is the point."""
    email = make_email(
        links=[make_link("https://sakura-bank.example/out?next=https://evil.example/")]
    )
    assert len(open_redirect.check(email, context)) == 1


def test_the_same_pair_is_reported_once(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("https://trusted.example/r?url=https://evil.example/a"),
            make_link("https://trusted.example/r?url=https://evil.example/b"),
        ]
    )
    assert len(open_redirect.check(email, context)) == 1


def test_different_destinations_are_reported_separately(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("https://trusted.example/r?url=https://evil.example/a"),
            make_link("https://trusted.example/r?url=https://worse.example/b"),
        ]
    )
    assert len(open_redirect.check(email, context)) == 2


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


def test_a_plain_link_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("https://sakura-bank.example/login")])
    assert open_redirect.check(email, context) == []


def test_a_redirect_inside_the_same_site_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """Ordinary click tracking."""
    email = make_email(
        links=[
            make_link(
                "https://nijiiro-shop.example/r?url=https://nijiiro-shop.example/sale"
            )
        ]
    )
    assert open_redirect.check(email, context) == []


def test_a_redirect_between_domains_of_one_organization_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """The second false positive the whitelist exists to prevent."""
    email = make_email(
        links=[
            make_link(
                "https://nijiiro-shop-mail.example/c?url=https://nijiiro-shop.example/sale"
            )
        ]
    )
    assert open_redirect.check(email, context) == []


def test_a_search_query_containing_a_url_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """``q`` is not a redirect parameter, so this is just a search."""
    email = make_email(
        links=[make_link("https://search.nijiiro-shop.example/?q=https://evil.example")]
    )
    assert open_redirect.check(email, context) == []


def test_a_relative_redirect_target_is_not_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[make_link("https://sakura-bank.example/login?next=/account")]
    )
    assert open_redirect.check(email, context) == []


def test_an_email_without_links(make_email: MakeEmail, context: RuleContext) -> None:
    assert open_redirect.check(make_email(body_text="本文のみ"), context) == []
