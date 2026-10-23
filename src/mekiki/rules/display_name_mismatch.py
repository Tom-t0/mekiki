"""Rule: the sender's display name does not fit the address it came from.

Gmail shows the display name prominently and the address faintly, so
"さくら銀行" over ``info@sakura-bamk.example`` reads as the bank to most
people.

Two ways the name can disagree with the address:

1. The name itself contains a host or an address that points somewhere else.
2. The name claims an organization in the whitelist, and the address is not on
   any of that organization's domains.

Known limitation: the second check can only speak about organizations the
whitelist knows. An unlisted company is not judged here, which is the right
failure direction - silence rather than a guess.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding
from mekiki.urls import email_address_domain, host_claimed_in_text, same_registrable_domain

SIGNAL = SpoofSignal.DISPLAY_NAME_MISMATCH


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """At most one finding: the sender is one thing, so it is one piece of
    evidence, even when both checks have something to say."""
    display_name = email.sender_display_name
    address_domain = email_address_domain(email.sender_address)
    if not display_name or not address_domain:
        return []

    reasons: list[str] = []

    # (1) A host written into the display name itself.
    claimed_host = host_claimed_in_text(display_name, include_email_addresses=True)
    if claimed_host is not None and not same_registrable_domain(
        claimed_host, address_domain
    ):
        claimed_owner = context.whitelist.entry_for_host(claimed_host)
        if claimed_owner is None or not claimed_owner.owns_host(address_domain):
            reasons.append(
                f"display name claims {claimed_host} but the address is on "
                f"{address_domain}"
            )

    # (2) An organization claimed by name.
    claimed_entry = context.whitelist.entry_claimed_in(display_name)
    if claimed_entry is not None and not claimed_entry.owns_host(address_domain):
        reasons.append(
            f"display name claims to be {claimed_entry.entity}, whose domains are "
            f"{', '.join(claimed_entry.domains)}, but the address is on "
            f"{address_domain}"
        )

    if not reasons:
        return []
    return [
        RuleFinding(
            signal=SIGNAL,
            quote=f"{display_name} <{email.sender_address}>",
            detail="; ".join(reasons),
        )
    ]


RULE = Rule(signal=SIGNAL, check=check)
