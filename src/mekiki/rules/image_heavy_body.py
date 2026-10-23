"""Rule: the body is mostly images with almost no text.

Putting the whole message inside an image defeats text based filtering, and it
also defeats this tool's own text analysis, so the shape of the email is worth
recording even though the text cannot be read.

Thresholds are deliberately stated as module constants: they are a judgement
call, not a fact, and they belong somewhere a reader can find and argue with.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding

SIGNAL = SpoofSignal.IMAGE_HEAVY_BODY

MIN_IMAGE_COUNT = 2
"""A single image is an ordinary logo or banner, so one is not enough."""

MAX_TEXT_LENGTH = 100
"""Characters of visible text below which the body is not carrying the
message itself.

Set from the test that matters: a genuine image rich newsletter still writes
about 150 characters of Japanese, so a limit of 200 flagged it. Phishing that
hides its text in an image has almost none."""


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """At most one finding: this is a property of the whole body."""
    if email.image_count < MIN_IMAGE_COUNT:
        return []
    if email.text_length > MAX_TEXT_LENGTH:
        return []
    return [
        RuleFinding(
            signal=SIGNAL,
            # There is no text to quote, so the measurement is the evidence.
            quote=f"本文テキスト{email.text_length}文字 / 画像{email.image_count}枚",
            detail=(
                f"text_length={email.text_length} (<= {MAX_TEXT_LENGTH}), "
                f"image_count={email.image_count} (>= {MIN_IMAGE_COUNT})"
            ),
        )
    ]


RULE = Rule(signal=SIGNAL, check=check)
