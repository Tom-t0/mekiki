"""Rule: the body contains a QR code. INTERFACE ONLY.

Not implemented yet, on purpose. What it will need:

- The image bytes. ``NormalizedEmail`` carries only ``image_count`` today,
  because the extension does not download images. Adding a field for image
  data changes the privacy story of the input type, so it is a decision to
  take deliberately rather than in passing.
- A QR decoder, which is a real dependency and the first piece of this
  project that would not be readable from the source alone.

Note that axis 3 already has ``scan_qr``: the LLM can observe from the text
that the reader is being asked to scan something, even while this mechanical
check is missing.

The registry marks this rule as not implemented and skips it.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding

SIGNAL = SpoofSignal.EMBEDDED_QR


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """Planned: decode QR codes out of the inline images."""
    raise NotImplementedError(
        "embedded_qr needs image data and a decoder; see the module docstring"
    )


RULE = Rule(signal=SIGNAL, check=check, implemented=False)
