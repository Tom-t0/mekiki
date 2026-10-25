"""Tests for the lookalike_domain rule."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from mekiki.email_input import EmailLink, NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import lookalike_domain
from mekiki.rules.base import RuleContext

MakeEmail = Callable[..., NormalizedEmail]
MakeLink = Callable[..., EmailLink]


# --------------------------------------------------------------------------
# Must fire
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected_in_detail"),
    [
        # One substitution.
        ("sakura-bamk.example", "1 edit away from sakura-bank.example"),
        # One deletion.
        ("sakurabank.example", "1 edit away from sakura-bank.example"),
        # One insertion.
        ("sakura-bannk.example", "1 edit away from sakura-bank.example"),
        # rn drawn as m.
        ("rnidori-card.example", "characters drawn like midori-card.example"),
        # A digit used as a letter.
        ("s0rapay.example", "characters drawn like sorapay.example"),
        # The same name under a different suffix.
        ("sakura-bank.test", "the name of sakura-bank.example under a different suffix"),
    ],
)
def test_sender_domain_imitating_a_known_domain(
    host: str, expected_in_detail: str, make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(sender_address=f"info@{host}")
    findings = lookalike_domain.check(email, context)
    assert [finding.signal for finding in findings] == [SpoofSignal.LOOKALIKE_DOMAIN]
    assert findings[0].quote == host
    assert findings[0].detail == expected_in_detail


def test_cyrillic_homograph_is_reported(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """The a and the second a here are Cyrillic."""
    email = make_email(sender_address="info@sаkura-bаnk.example")
    findings = lookalike_domain.check(email, context)
    assert len(findings) == 1
    assert "characters drawn like sakura-bank.example" == findings[0].detail


def test_punycode_of_a_known_name_is_reported(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """xn--sakura-bnk-xh4b.example decodes to sakura-bаnk.example (Cyrillic а)."""
    host = "sаkura-bаnk.example".encode("idna").decode("ascii")
    email = make_email(links=[make_link(f"https://{host}/login")])
    findings = lookalike_domain.check(email, context)
    assert len(findings) == 1
    assert findings[0].detail == "characters drawn like sakura-bank.example"


def test_a_link_host_is_checked_too(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(links=[make_link("https://login.sakura-bamk.example/")])
    findings = lookalike_domain.check(email, context)
    assert len(findings) == 1
    assert findings[0].quote == "login.sakura-bamk.example"


def test_the_same_domain_is_reported_once(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        sender_address="info@sakura-bamk.example",
        links=[
            make_link("https://sakura-bamk.example/a"),
            make_link("https://mail.sakura-bamk.example/b"),
        ],
    )
    assert len(lookalike_domain.check(email, context)) == 1


def test_distinct_imitations_are_reported_separately(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        links=[
            make_link("https://sakura-bamk.example/a"),
            make_link("https://rnidori-card.example/b"),
        ]
    )
    assert len(lookalike_domain.check(email, context)) == 2


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


def test_the_genuine_domain_is_not_an_imitation_of_itself(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="info@sakura-bank.example",
        links=[make_link("https://sakura-bank.example/statement", "ご利用明細")],
    )
    assert lookalike_domain.check(email, context) == []


def test_a_subdomain_of_a_genuine_domain(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        sender_address="info@mail.sakura-bank.example",
        links=[make_link("https://login.sakura-bank.example/")],
    )
    assert lookalike_domain.check(email, context) == []


def test_a_second_legitimate_domain_of_the_same_organization(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """sakura-bank-mail.example is 5 edits from sakura-bank.example, but it is
    whitelisted, so it is never compared in the first place."""
    email = make_email(sender_address="news@sakura-bank-mail.example")
    assert lookalike_domain.check(email, context) == []


def test_an_unrelated_domain(make_email: MakeEmail, context: RuleContext) -> None:
    email = make_email(sender_address="info@totally-different.example")
    assert lookalike_domain.check(email, context) == []


def test_an_unrelated_japanese_company(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="どこか株式会社",
        sender_address="info@example.co.jp",
        links=[make_link("https://www.example.co.jp/news", "お知らせ")],
    )
    assert lookalike_domain.check(email, context) == []


def test_an_ip_address_is_not_a_lookalike(
    make_email: MakeEmail, make_link: MakeLink, context: RuleContext
) -> None:
    """That is what the ip_address_url rule is for."""
    email = make_email(links=[make_link("http://203.0.113.5/login")])
    assert lookalike_domain.check(email, context) == []


def test_a_short_name_one_edit_away_is_not_reported(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """With a short whitelisted name, one edit is a different word.

    "sorapay" is 7 characters so it is compared; a 4 character entry would
    not be. This checks the guard with a custom whitelist.
    """
    from mekiki.whitelist import Whitelist, WhitelistEntry

    whitelist = Whitelist(
        schema_version=1,
        entries=[WhitelistEntry(entity="ソラ", domains=["sora.example"])],
    )
    email = make_email(sender_address="info@sera.example")
    assert lookalike_domain.check(email, RuleContext(whitelist=whitelist)) == []


def test_an_email_with_nothing_to_check(
    make_email: MakeEmail, context: RuleContext
) -> None:
    assert lookalike_domain.check(make_email(body_text="本文のみ"), context) == []
