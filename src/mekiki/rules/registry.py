"""The list of axis 4 rules and how to run them.

Adding a rule means writing one module and adding one line here. Rules that
exist only as an interface stay in the list but are skipped, so the catalogue
of signals stays visible in one place without an unfinished rule being able to
break an analysis.
"""

from __future__ import annotations

from mekiki.email_input import NormalizedEmail
from mekiki.labels import SpoofSignal
from mekiki.rules import (
    display_name_mismatch,
    embedded_qr,
    image_heavy_body,
    ip_address_url,
    known_malicious,
    link_mismatch,
    lookalike_domain,
    open_redirect,
    url_shortener,
)
from mekiki.rules.base import Rule, RuleContext, RuleFinding, signals_of

ALL_RULES: tuple[Rule, ...] = (
    display_name_mismatch.RULE,
    link_mismatch.RULE,
    lookalike_domain.RULE,
    url_shortener.RULE,
    open_redirect.RULE,
    ip_address_url.RULE,
    image_heavy_body.RULE,
    # Interface only for now.
    embedded_qr.RULE,
    known_malicious.RULE,
)

IMPLEMENTED_RULES: tuple[Rule, ...] = tuple(
    rule for rule in ALL_RULES if rule.implemented
)

PLANNED_RULES: tuple[Rule, ...] = tuple(
    rule for rule in ALL_RULES if not rule.implemented
)


def run_rules(
    email: NormalizedEmail, context: RuleContext | None = None
) -> list[RuleFinding]:
    """Run every implemented rule, in registry order.

    The order of the findings follows the order of the rules, so the output is
    reproducible and a test can assert on it.
    """
    active_context = context if context is not None else RuleContext.default()
    findings: list[RuleFinding] = []
    for rule in IMPLEMENTED_RULES:
        findings.extend(rule.check(email, active_context))
    return findings


def detected_signals(
    email: NormalizedEmail, context: RuleContext | None = None
) -> list[SpoofSignal]:
    """The axis 4 labels for an email: distinct signals, in rule order."""
    return signals_of(run_rules(email, context))
