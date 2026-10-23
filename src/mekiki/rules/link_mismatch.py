"""Rule: the link text names one site and the link goes to another.

This is the oldest trick in phishing: write ``sakura-bank.example`` on screen
and point the anchor at ``sakura-bamk.example``. Only link text that actually
names a site is compared; "ご確認はこちら" claims nothing and is left alone.

The whitelist matters here. A real company often writes its main domain in the
text while the anchor goes to its mail or tracking domain, and that is not
spoofing, so two domains owned by the same listed organization do not count as
a mismatch.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding
from mekiki.urls import extract_host, host_claimed_in_text, same_registrable_domain

SIGNAL = SpoofSignal.LINK_MISMATCH


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """One finding per link whose text names a different site."""
    findings: list[RuleFinding] = []
    for link in email.links:
        actual_host = extract_host(link.href)
        if actual_host is None:
            continue
        # An address in link text is contact information, not a destination.
        claimed = host_claimed_in_text(link.display_text)
        if claimed is None:
            continue
        if same_registrable_domain(claimed, actual_host):
            continue

        # Both domains owned by the same listed organization is not spoofing.
        claimed_owner = context.whitelist.entry_for_host(claimed)
        if claimed_owner is not None and claimed_owner.owns_host(actual_host):
            continue

        findings.append(
            RuleFinding(
                signal=SIGNAL,
                # The mismatch *is* the pair, so the pair is the evidence.
                quote=f"{link.display_text} → {link.href}",
                detail=f"link text claims {claimed} but the link goes to {actual_host}",
            )
        )
    return findings


RULE = Rule(signal=SIGNAL, check=check)
