"""Tests for the image_heavy_body rule."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import image_heavy_body
from mekiki.rules.base import RuleContext
from mekiki.rules.image_heavy_body import MAX_TEXT_LENGTH, MIN_IMAGE_COUNT

MakeEmail = Callable[..., NormalizedEmail]


def test_image_only_body_is_reported(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(body_text="", image_count=3)
    findings = image_heavy_body.check(email, context)
    assert [finding.signal for finding in findings] == [SpoofSignal.IMAGE_HEAVY_BODY]
    # There is no text to quote, so the measurement is the evidence.
    assert findings[0].quote == "本文テキスト0文字 / 画像3枚"


def test_a_short_caption_still_counts_as_image_heavy(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(body_text="詳細は画像をご覧ください。", image_count=4)
    assert len(image_heavy_body.check(email, context)) == 1


def test_only_one_finding_is_produced(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """This is a property of the whole body, not of each image."""
    email = make_email(body_text="", image_count=20)
    assert len(image_heavy_body.check(email, context)) == 1


@pytest.mark.parametrize("image_count", [MIN_IMAGE_COUNT, MIN_IMAGE_COUNT + 1])
def test_at_and_above_the_image_threshold(
    image_count: int, make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(body_text="", image_count=image_count)
    assert len(image_heavy_body.check(email, context)) == 1


def test_at_the_text_length_threshold(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(body_text="あ" * MAX_TEXT_LENGTH, image_count=2)
    assert len(image_heavy_body.check(email, context)) == 1


# --------------------------------------------------------------------------
# Must not fire
# --------------------------------------------------------------------------


@pytest.mark.parametrize("image_count", [0, MIN_IMAGE_COUNT - 1])
def test_below_the_image_threshold(
    image_count: int, make_email: MakeEmail, context: RuleContext
) -> None:
    """A single banner or logo is ordinary."""
    email = make_email(body_text="", image_count=image_count)
    assert image_heavy_body.check(email, context) == []


def test_just_above_the_text_length_threshold(
    make_email: MakeEmail, context: RuleContext
) -> None:
    email = make_email(body_text="あ" * (MAX_TEXT_LENGTH + 1), image_count=2)
    assert image_heavy_body.check(email, context) == []


def test_a_real_newsletter_with_many_images_is_not_reported(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """Legitimate marketing mail is image rich but still carries its text."""
    email = make_email(
        sender_display_name="ニジイロ通販",
        sender_address="news@nijiiro-shop.example",
        body_text=(
            "いつもニジイロ通販をご利用いただきありがとうございます。"
            "本日より春の大感謝セールを開催いたします。"
            "対象商品は約3000点、期間は4月1日から4月14日までです。"
            "送料無料の条件や返品のご案内は、下記のリンクからご確認ください。"
            "今回のセールでは、衣料品に加えて食品と日用品も対象となりました。"
        ),
        image_count=12,
    )
    assert image_heavy_body.check(email, context) == []


def test_an_empty_email_is_not_reported(
    make_email: MakeEmail, context: RuleContext
) -> None:
    """Nothing at all is a missing_content case, not a spoofing signal."""
    assert image_heavy_body.check(make_email(), context) == []
