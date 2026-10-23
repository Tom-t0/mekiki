"""Rule: a domain is built to be mistaken for a known one.

Three ways a domain can imitate another, all measured against the whitelist
because "looks like" needs something to look like:

1. Confusable characters: ``rnidori-card.example`` for ``midori-card.example``,
   or Cyrillic letters drawn like Latin ones.
2. One edit away: ``sakura-bamk.example``, ``sakurabank.example``.
3. The same name under a different public suffix: ``sakura-bank.test`` for
   ``sakura-bank.example``.

The arithmetic behind "close enough" is in :mod:`mekiki.similarity` and is
written out by hand, since this is the one rule that makes a judgement call
about similarity.

Known trade-off for case 3: a company that genuinely owns the same name under
several suffixes will be flagged unless every one of them is in the
whitelist. The whitelist is the stated source of truth for an organization's
legitimate domains, so that is a data problem rather than a rule problem.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules.base import Rule, RuleContext, RuleFinding
from mekiki.similarity import levenshtein, normalize_confusables
from mekiki.urls import (
    decode_punycode,
    email_address_domain,
    extract_host,
    is_ip_host,
    is_punycode,
    registrable_domain,
)

SIGNAL = SpoofSignal.LOOKALIKE_DOMAIN

MAX_EDIT_DISTANCE = 1
"""How many edits still count as a lookalike.

One, not two: at two, unrelated short domains start matching each other. The
cost is that a swapped pair of letters (``bnak`` for ``bank``) is two edits
and is missed, which the confusable table partly makes up for.
"""

MIN_COMPARABLE_NAME_LENGTH = 6
"""Shortest whitelisted name that edit distance is applied to.

For a four letter name, one edit is a different word rather than a lookalike.
"""


def _name_part(domain: str) -> str:
    """The registered label of a domain: ``sakura-bank`` of
    ``sakura-bank.example``."""
    return domain.split(".", 1)[0]


def _suffix_part(domain: str) -> str:
    """Everything after the registered label."""
    return domain.partition(".")[2]


def _candidate_hosts(email: NormalizedEmail) -> list[str]:
    """Every host this email points at, sender first, without duplicates."""
    hosts: list[str] = []
    sender_domain = email_address_domain(email.sender_address)
    if sender_domain:
        hosts.append(sender_domain)
    for link in email.links:
        host = extract_host(link.href)
        if host:
            hosts.append(host)

    seen: set[str] = set()
    unique: list[str] = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return unique


def _imitation_reason(domain: str, legitimate_domain: str) -> str | None:
    """Why ``domain`` looks like ``legitimate_domain``, or ``None``."""
    # Punycode on its own is not suspicious; a punycode host that looks like a
    # known brand is. Comparing them needs the decoded form.
    decoded = decode_punycode(domain) if is_punycode(domain) else domain
    normalized = normalize_confusables(decoded)
    normalized_legitimate = normalize_confusables(legitimate_domain)

    if normalized == normalized_legitimate:
        return f"characters drawn like {legitimate_domain}"

    if normalize_confusables(_name_part(decoded)) == normalize_confusables(
        _name_part(legitimate_domain)
    ) and _suffix_part(decoded) != _suffix_part(legitimate_domain):
        return f"the name of {legitimate_domain} under a different suffix"

    if len(_name_part(legitimate_domain)) >= MIN_COMPARABLE_NAME_LENGTH:
        distance = levenshtein(normalized, normalized_legitimate)
        if 0 < distance <= MAX_EDIT_DISTANCE:
            return f"{distance} edit away from {legitimate_domain}"

    return None


def check(email: NormalizedEmail, context: RuleContext) -> list[RuleFinding]:
    """One finding per distinct imitating domain."""
    findings: list[RuleFinding] = []
    reported: set[str] = set()

    for host in _candidate_hosts(email):
        # The genuine domain is not an imitation of itself.
        if context.whitelist.knows_host(host):
            continue
        domain = registrable_domain(host)
        if domain is None or is_ip_host(domain) or domain in reported:
            continue

        for legitimate_domain in context.whitelist.all_domains:
            reason = _imitation_reason(domain, legitimate_domain)
            if reason is None:
                continue
            reported.add(domain)
            findings.append(
                RuleFinding(signal=SIGNAL, quote=host, detail=reason)
            )
            break

    return findings


RULE = Rule(signal=SIGNAL, check=check)
