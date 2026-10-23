"""Rule: a link points at a bare IP address.

A real company serves its site from a domain name, because a certificate and a
brand are attached to it. A link straight to ``http://203.0.113.5/login`` is a
host that nobody bothered to name, which is what a throwaway phishing server
looks like.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding
from mekiki.urls import extract_host, is_ip_host

SIGNAL = SpoofSignal.IP_ADDRESS_URL


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """One finding per distinct IP host, keeping the first link that used it."""
    findings: list[RuleFinding] = []
    reported: set[str] = set()
    for link in email.links:
        host = extract_host(link.href)
        if not is_ip_host(host) or host in reported:
            continue
        reported.add(str(host))
        findings.append(
            RuleFinding(
                signal=SIGNAL,
                quote=link.href,
                detail=f"link host is a bare IP address: {host}",
            )
        )
    return findings


RULE = Rule(signal=SIGNAL, check=check)
