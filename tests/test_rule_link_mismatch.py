"""Tests for the link_mismatch rule."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from mekiki.email_input import EmailLink, NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import link_mismatch
from mekiki.rules.base import RuleContext
from mekiki.urls import host_claimed_in_text as claimed_host

MakeEmail = Callable[..., NormalizedEmail]
MakeLink = Callable[..., EmailLink]


# --------------------------------------------------------------------------
# claimed_host: what the link text claims, on its own
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("display_text", "expected"),
    [
        ("https://sakura-bank.example/login", "sakura-bank.example"),
        ("sakura-bank.example", "sakura-bank.example"),
        ("www.sakura-bank.example", "www.sakura-bank.example"),
        ("詳細は sakura-bank.example をご覧ください", "sakura-bank.example"),
        ("【さくら銀行】https://sakura-bank.example/", "sakura-bank.example"),
        # A full URL is the more explicit claim and wins.
        ("other.example https://sakura-bank.example/", "sakura-bank.example"),
    ],
)
def test_claimed_host_is_found(display_text: str, expected: str) -> None:
    assert claimed_host(display_text) == expected


@pytest.mark.parametrize(
    "display_text",
    [
        "",
        "ご確認はこちら",
        "ログイン",
        "Click here",
        # Contact information is not a claim about the destination.
        "お問い合わせ: support@sakura-bank.example",
        # File names are not hosts.
        "campaign.png",
        "ご利用明細.pdf",
        # A single word with no dot.
        "sakurabank",
    ],
)
def test_no_host_is_claimed(display_text: str) -> None:
    assert claimed_host(display_text) is None


# --------------------------------------------------------------------------
# Must fire
# --------------------------------------------------------------------------


def test_text_and_destination_disagree(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[make_link("https://sakura-bamk.example/login", "sakura-bank.example")]
    )
    findings = link_mismatch.check(email, context)
    assert [finding.signal for finding in findings] == [SpoofSignal.LINK_MISMATCH]
    assert findings[0].quote == "sakura-bank.example → https://sakura-bamk.example/login"


def test_full_url_in_the_text_disagrees(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link(
                "https://evil.example/login", "https://sakura-bank.example/login"
            )
        ]
    )
    assert len(link_mismatch.check(email, context)) == 1


def test_a_different_organization_is_a_mismatch(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """Both domains are whitelisted, but not to the same owner."""
    email = make_email(
        links=[make_link("https://midori-card.example/x", "sakura-bank.example")]
    )
    assert len(link_mismatch.check(email, context)) == 1


def test_each_bad_link_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("https://evil.example/a", "sakura-bank.example"),
            make_link("https://evil.example/b", "midori-card.example"),
        ]
    )
    assert len(link_mismatch.check(email, context)) == 2


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


def test_matching_text_and_destination(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("https://sakura-bank.example/login", "sakura-bank.example")
        ]
    )
    assert link_mismatch.check(email, context) == []


def test_a_subdomain_of_the_claimed_site(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """The owner is the same, so this is not a mismatch."""
    email = make_email(
        links=[
            make_link("https://login.sakura-bank.example/", "sakura-bank.example")
        ]
    )
    assert link_mismatch.check(email, context) == []


def test_two_domains_of_the_same_listed_organization(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """The false positive the whitelist exists to prevent.

    The bank writes its main domain in the text but sends the click through
    its mail domain.
    """
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="info@sakura-bank-mail.example",
        links=[
            make_link(
                "https://sakura-bank-mail.example/track/1", "sakura-bank.example"
            )
        ],
    )
    assert link_mismatch.check(email, context) == []


def test_link_text_without_any_claim(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """Japanese call to action text is the common case and claims nothing."""
    email = make_email(
        links=[make_link("https://tracking.example/abc", "ご確認はこちら")]
    )
    assert link_mismatch.check(email, context) == []


def test_non_web_destination_is_ignored(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("mailto:support@evil.example", "sakura-bank.example")
        ]
    )
    assert link_mismatch.check(email, context) == []


def test_an_email_without_links(make_email: MakeEmail, context: RuleContext) -> None:
    assert link_mismatch.check(make_email(body_text="本文のみ"), context) == []
