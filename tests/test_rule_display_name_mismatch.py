"""Tests for the display_name_mismatch rule."""

from __future__ import annotations

from collections.abc import Callable

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import display_name_mismatch
from mekiki.rules.base import RuleContext

MakeEmail = Callable[..., NormalizedEmail]


# --------------------------------------------------------------------------
# Must fire
# --------------------------------------------------------------------------


def test_claimed_organization_with_a_foreign_address(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="info@sakura-bamk.example",
    )
    findings = display_name_mismatch.check(email, context)
    assert [finding.signal for finding in findings] == [
        SpoofSignal.DISPLAY_NAME_MISMATCH
    ]
    assert findings[0].quote == "さくら銀行 <info@sakura-bamk.example>"


def test_decorated_display_name_still_claims_the_organization(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="【さくら銀行】カスタマーセンター",
        sender_address="support@free-mail.example",
    )
    assert len(display_name_mismatch.check(email, context)) == 1


def test_an_alias_counts_as_a_claim(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="Sakura Bank Support",
        sender_address="support@free-mail.example",
    )
    assert len(display_name_mismatch.check(email, context)) == 1


def test_a_domain_written_into_the_display_name(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """Works for organizations the whitelist has never heard of."""
    email = make_email(
        sender_display_name="dokoka-shop.example",
        sender_address="info@evil.example",
    )
    findings = display_name_mismatch.check(email, context)
    assert len(findings) == 1
    assert "dokoka-shop.example" in findings[0].detail


def test_an_address_written_into_the_display_name(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """In a display name an address is a claim about who is writing."""
    email = make_email(
        sender_display_name="info@sakura-bank.example",
        sender_address="attacker@evil.example",
    )
    assert len(display_name_mismatch.check(email, context)) == 1


def test_both_reasons_produce_one_finding(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """The sender is one thing, so it is one piece of evidence."""
    email = make_email(
        sender_display_name="さくら銀行 (sakura-bank.example)",
        sender_address="info@evil.example",
    )
    findings = display_name_mismatch.check(email, context)
    assert len(findings) == 1
    assert findings[0].detail.count(";") == 1


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


def test_the_real_bank(make_email: MakeEmail, context: RuleContext) -> None:
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="info@sakura-bank.example",
    )
    assert display_name_mismatch.check(email, context) == []


def test_a_second_legitimate_domain_of_the_same_organization(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """The false positive the whitelist exists to prevent."""
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="news@sakura-bank-mail.example",
    )
    assert display_name_mismatch.check(email, context) == []


def test_a_subdomain_of_a_legitimate_domain(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="さくら銀行",
        sender_address="info@mail.sakura-bank.example",
    )
    assert display_name_mismatch.check(email, context) == []


def test_an_unlisted_organization_is_not_judged(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """Silence is the right answer when there is nothing to compare against."""
    email = make_email(
        sender_display_name="どこか株式会社",
        sender_address="info@dokoka.example",
    )
    assert display_name_mismatch.check(email, context) == []


def test_a_display_name_that_is_only_a_person(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="田中太郎",
        sender_address="tanaka@dokoka.example",
    )
    assert display_name_mismatch.check(email, context) == []


def test_a_matching_domain_in_the_display_name(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(
        sender_display_name="ニジイロ通販 (nijiiro-shop.example)",
        sender_address="news@nijiiro-shop.example",
    )
    assert display_name_mismatch.check(email, context) == []


def test_missing_fields_produce_nothing(
    make_email: MakeEmail, context: RuleContext
) -> None:
    assert display_name_mismatch.check(make_email(), context) == []
    assert (
        display_name_mismatch.check(make_email(sender_display_name="さくら銀行"), context)
        == []
    )
    assert (
        display_name_mismatch.check(
            make_email(sender_address="info@sakura-bank.example"), context
        )
        == []
    )
