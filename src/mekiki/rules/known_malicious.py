"""Rule: a link appears on a known malicious list. INTERFACE ONLY.

Not implemented yet, on purpose. What it will need:

- A blocklist snapshot stored locally and refreshed out of band, so that
  analysing an email still touches no network. Looking a URL up in a live
  reputation API would mean sending the user's mail contents to a third party,
  which is exactly what this tool should not do.
- A decision about which list, and the licence terms that come with it.

The registry marks this rule as not implemented and skips it, so an analysis
never calls ``check`` and never sees the exception below. When the blocklist
lands, only ``check`` and ``implemented`` change; nothing else in the project
has to move.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding

SIGNAL = SpoofSignal.KNOWN_MALICIOUS


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """Planned: match every link host against a local blocklist snapshot."""
    raise NotImplementedError(
        "known_malicious needs a local blocklist snapshot; see the module docstring"
    )


RULE = Rule(signal=SIGNAL, check=check, implemented=False)
