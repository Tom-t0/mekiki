"""Tests for the whitelist and the sender category table."""

from __future__ import annotations

import pytest

from mekiki.labels import SenderCategory
from mekiki.resources_io import load_domain_list
from mekiki.whitelist import (
    SenderCategoryTable,
    Whitelist,
    WhitelistEntry,
    load_sender_categories,
    load_whitelist,
    normalize_entity_name,
    sender_category_for_display_name,
)

RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost")

# --------------------------------------------------------------------------
# Safety: the sample data must stay fictional
# --------------------------------------------------------------------------


def test_every_sample_domain_is_in_a_reserved_namespace() -> None:
    """A regression test for the project's own safety rule.

    RFC 2606 reserves these names, so nothing in the sample data can ever
    point at a real company.
    """
    for domain in load_whitelist().all_domains:
        assert domain.endswith(RESERVED_SUFFIXES), domain


def test_sample_domains_are_unique() -> None:
    domains = load_whitelist().all_domains
    assert len(domains) == len(set(domains))


def test_every_organization_has_a_distinct_registrable_domain() -> None:
    """Fictional names must not collapse onto one domain.

    Using ``sakura-bank.example.com`` style names would make every
    organization share the registrable domain ``example.com``, and the link
    rules would then see everything as the same owner.
    """
    from mekiki.urls import registrable_domain

    for entry in load_whitelist().entries:
        for domain in entry.domains:
            assert registrable_domain(domain) == domain, domain


# --------------------------------------------------------------------------
# Loading the packaged files
# --------------------------------------------------------------------------


def test_whitelist_loads_and_is_not_empty() -> None:
    whitelist = load_whitelist()
    assert whitelist.schema_version == 1
    assert len(whitelist.entries) >= 5


def test_every_whitelisted_entity_has_a_category() -> None:
    categories = load_sender_categories()
    for entry in load_whitelist().entries:
        assert categories.category_for(entry.entity) is not SenderCategory.OTHER


def test_shortener_list_loads_and_ignores_comments() -> None:
    shorteners = load_domain_list("shorteners.txt")
    assert "bit.ly" in shorteners
    assert not any(domain.startswith("#") for domain in shorteners)
    assert "" not in shorteners


# --------------------------------------------------------------------------
# normalize_entity_name
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("さくら銀行", "【さくら銀行】"),
        ("さくら銀行", "さくら銀行"),
        ("さくら銀行", "さくら 銀行"),
        ("Sakura Bank", "sakurabank"),
        ("Sakura Bank", "ＳＡＫＵＲＡ　ＢＡＮＫ"),
    ],
)
def test_entity_names_compare_equal_after_normalization(left: str, right: str) -> None:
    assert normalize_entity_name(left) == normalize_entity_name(right)


def test_different_organizations_do_not_normalize_to_the_same_name() -> None:
    assert normalize_entity_name("さくら銀行") != normalize_entity_name("ミドリカード")


# --------------------------------------------------------------------------
# Domain ownership
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected_entity"),
    [
        ("sakura-bank.example", "さくら銀行"),
        # A second legitimate domain of the same organization.
        ("sakura-bank-mail.example", "さくら銀行"),
        # Subdomains belong to the owner.
        ("mail.sakura-bank.example", "さくら銀行"),
        ("midori-card.example", "ミドリカード"),
        # Not whitelisted.
        ("sakura-bamk.example", None),
        ("evil.example", None),
        # Suffix matching without a dot boundary would wrongly accept this.
        ("notsakura-bank.example", None),
        ("sakura-bank.example.evil.example", None),
        (None, None),
    ],
)
def test_entry_for_host(host: str | None, expected_entity: str | None) -> None:
    entry = load_whitelist().entry_for_host(host)
    assert (entry.entity if entry else None) == expected_entity


def test_knows_host() -> None:
    whitelist = load_whitelist()
    assert whitelist.knows_host("mail.sorapay.example") is True
    assert whitelist.knows_host("sorapay-support.example") is False


# --------------------------------------------------------------------------
# Claimed entity in a display name
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("display_name", "expected_entity"),
    [
        ("さくら銀行", "さくら銀行"),
        ("【さくら銀行】カスタマーセンター", "さくら銀行"),
        ("サクラ銀行", "さくら銀行"),
        ("Sakura Bank Support", "さくら銀行"),
        ("ニジイロ通販 カスタマーサポート", "ニジイロ通販"),
        ("架空市役所 税務課", "架空市役所"),
        # No known organization claimed.
        ("田中太郎", None),
        ("", None),
        (None, None),
    ],
)
def test_entry_claimed_in(display_name: str | None, expected_entity: str | None) -> None:
    entry = load_whitelist().entry_claimed_in(display_name)
    assert (entry.entity if entry else None) == expected_entity


def test_the_longest_matching_name_wins() -> None:
    """An entry whose name contains another entry's name must not shadow it."""
    whitelist = Whitelist(
        schema_version=1,
        entries=[
            WhitelistEntry(entity="ミドリ", domains=["midori.example"]),
            WhitelistEntry(entity="ミドリカード", domains=["midori-card.example"]),
        ],
    )
    entry = whitelist.entry_claimed_in("ミドリカードのご案内")
    assert entry is not None
    assert entry.entity == "ミドリカード"


def test_entry_for_entity_accepts_aliases() -> None:
    whitelist = load_whitelist()
    assert whitelist.entry_for_entity("Sakura Bank") is whitelist.entry_for_entity(
        "さくら銀行"
    )
    assert whitelist.entry_for_entity("存在しない組織") is None


# --------------------------------------------------------------------------
# Axis 1: category lookup
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entity", "expected"),
    [
        ("さくら銀行", SenderCategory.BANK),
        ("ミドリカード", SenderCategory.CARD),
        ("ハルカ証券", SenderCategory.SECURITIES),
        ("架空市役所", SenderCategory.PUBLIC_AGENCY),
        # Unlisted senders are a normal situation, not an error.
        ("どこかの会社", SenderCategory.OTHER),
        (None, SenderCategory.OTHER),
    ],
)
def test_category_for(entity: str | None, expected: SenderCategory) -> None:
    assert load_sender_categories().category_for(entity) is expected


def test_category_lookup_is_decoration_insensitive() -> None:
    assert load_sender_categories().category_for("【さくら銀行】") is SenderCategory.BANK


def test_sender_category_for_display_name_end_to_end() -> None:
    assert sender_category_for_display_name("【さくら銀行】") is SenderCategory.BANK
    assert sender_category_for_display_name("Sakura Bank Support") is SenderCategory.BANK
    assert sender_category_for_display_name("田中太郎") is SenderCategory.OTHER


def test_unknown_category_value_is_rejected() -> None:
    """A typo in the data file must fail loudly at load time."""
    with pytest.raises(ValueError):
        SenderCategoryTable.model_validate(
            {"schema_version": 1, "categories": {"X": "banks"}}
        )


def test_entry_without_domains_is_rejected() -> None:
    with pytest.raises(ValueError):
        WhitelistEntry.model_validate({"entity": "X", "domains": []})
