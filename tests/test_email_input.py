"""Tests for the normalized input model."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mekiki.email_input import EmailLink, NormalizedEmail

# --------------------------------------------------------------------------
# Defaults and validation
# --------------------------------------------------------------------------


def test_an_empty_email_is_allowed_and_has_no_content() -> None:
    """The extension may hand over an email it failed to read."""
    email = NormalizedEmail()
    assert email.body_text == ""
    assert email.links == []
    assert email.image_count == 0
    assert email.has_analyzable_content() is False


def test_negative_image_count_is_rejected() -> None:
    with pytest.raises(ValidationError):
        NormalizedEmail(image_count=-1)


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        NormalizedEmail.model_validate({"body_text": "x", "sender_adress": "a@b.example"})


def test_the_email_cannot_be_modified_by_a_rule() -> None:
    email = NormalizedEmail(body_text="original")
    with pytest.raises(ValidationError):
        email.body_text = "tampered"  # type: ignore[misc]


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\n\t "])
def test_blank_optional_text_becomes_none(raw: str) -> None:
    """Screen scraping yields empty strings, which must not look like values."""
    email = NormalizedEmail(sender_display_name=raw, subject=raw, body_html=raw)
    assert email.sender_display_name is None
    assert email.subject is None
    assert email.body_html is None


def test_optional_text_is_stripped() -> None:
    email = NormalizedEmail(sender_display_name="  さくら銀行  ", subject=" ご案内 ")
    assert email.sender_display_name == "さくら銀行"
    assert email.subject == "ご案内"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Info@Sakura-Bank.Example", "Info@sakura-bank.example"),
        ("  info@SAKURA-BANK.EXAMPLE ", "info@sakura-bank.example"),
        # Only the last @ separates the domain.
        ("odd.local+part@mail@sakura-bank.EXAMPLE", "odd.local+part@mail@sakura-bank.example"),
        # Not an address at all: left untouched rather than guessed at.
        ("sakura-bank.example", "sakura-bank.example"),
    ],
)
def test_only_the_domain_part_of_the_address_is_lower_cased(
    raw: str, expected: str
) -> None:
    assert NormalizedEmail(sender_address=raw).sender_address == expected


def test_body_text_whitespace_is_normalized() -> None:
    email = NormalizedEmail(body_text="一行目\r\n二行目\r三行目 四行目")
    assert email.body_text == "一行目\n二行目\n三行目 四行目"


def test_text_length_ignores_surrounding_whitespace() -> None:
    assert NormalizedEmail(body_text="  \n abc \n ").text_length == 3


def test_link_display_text_defaults_to_empty_string() -> None:
    """An image wrapped in an anchor has no visible text."""
    link = EmailLink(href="https://sakura-bank.example/")
    assert link.display_text == ""


def test_link_fields_are_stripped() -> None:
    link = EmailLink(display_text="  ご確認はこちら ", href=" https://sakura-bank.example/ ")
    assert link.display_text == "ご確認はこちら"
    assert link.href == "https://sakura-bank.example/"


# --------------------------------------------------------------------------
# has_analyzable_content: the basis for verdict=undeterminable
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "email",
    [
        NormalizedEmail(body_text="ご利用明細のお知らせ"),
        NormalizedEmail(body_html="<p>ご利用明細</p>"),
        NormalizedEmail(links=[EmailLink(href="https://sakura-bank.example/")]),
        # An image only email has content, even though it has no text.
        NormalizedEmail(image_count=1),
    ],
)
def test_content_is_detected(email: NormalizedEmail) -> None:
    assert email.has_analyzable_content() is True


@pytest.mark.parametrize(
    "email",
    [
        NormalizedEmail(),
        NormalizedEmail(body_text="   \n  "),
        # A subject alone is not enough to judge the body.
        NormalizedEmail(subject="【重要】ご確認ください"),
        NormalizedEmail(sender_display_name="さくら銀行", sender_address="a@b.example"),
    ],
)
def test_missing_content_is_detected(email: NormalizedEmail) -> None:
    assert email.has_analyzable_content() is False
