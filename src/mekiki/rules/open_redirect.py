"""Rule: a link uses a redirector to reach a different site.

The visible host can be entirely respectable while a query parameter carries
the real destination: ``https://trusted.example/r?url=https://evil.example``.
The reader checks the first host and stops reading.

A redirect that stays inside the same site, or inside one listed
organization, is ordinary click tracking and is not reported.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding
from mekiki.urls import (
    extract_host,
    extract_redirect_urls,
    registrable_domain,
    same_registrable_domain,
)

SIGNAL = SpoofSignal.OPEN_REDIRECT


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """One finding per distinct redirector to destination pair."""
    findings: list[RuleFinding] = []
    reported: set[tuple[str, str]] = set()

    for link in email.links:
        redirector_host = extract_host(link.href)
        if redirector_host is None:
            continue

        for parameter_name, embedded_url in extract_redirect_urls(link.href):
            destination_host = extract_host(embedded_url)
            if destination_host is None:
                continue
            if same_registrable_domain(redirector_host, destination_host):
                continue

            redirector_owner = context.whitelist.entry_for_host(redirector_host)
            if redirector_owner is not None and redirector_owner.owns_host(
                destination_host
            ):
                continue

            key = (
                str(registrable_domain(redirector_host)),
                str(registrable_domain(destination_host)),
            )
            if key in reported:
                continue
            reported.add(key)

            findings.append(
                RuleFinding(
                    signal=SIGNAL,
                    quote=link.href,
                    detail=(
                        f"parameter '{parameter_name}' sends the reader from "
                        f"{redirector_host} to {destination_host}"
                    ),
                )
            )
    return findings


RULE = Rule(signal=SIGNAL, check=check)
