"""Rule: a link goes through a URL shortening service.

A shortener hides the destination, so the reader cannot judge where a link
goes and the other link rules cannot either. Legitimate senders do use
shorteners, especially in marketing mail, which is why this is one signal
among several and never a verdict on its own.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding
from mekiki.urls import extract_host, registrable_domain

SIGNAL = SpoofSignal.URL_SHORTENER


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """One finding per distinct shortener domain found in the links."""
    findings: list[RuleFinding] = []
    reported: set[str] = set()
    for link in email.links:
        host = extract_host(link.href)
        domain = registrable_domain(host)
        if domain is None or domain in reported:
            continue
        # Compare the registrable domain so that a subdomain of a shortener
        # (custom branded links) is caught as well.
        if domain not in context.shorteners:
            continue
        reported.add(domain)
        findings.append(
            RuleFinding(
                signal=SIGNAL,
                quote=link.href,
                detail=f"link uses the shortening service {domain}",
            )
        )
    return findings


RULE = Rule(signal=SIGNAL, check=check)
