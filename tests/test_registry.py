"""Tests for the rule registry, including the two interface only rules."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from mekiki.email_input import NormalizedEmail
from mekiki.labels import PHASE2_SIGNALS, SpoofSignal
from mekiki.rules import embedded_qr, known_malicious
from mekiki.rules.base import RuleContext, findings_to_evidence, signals_of
from mekiki.rules.registry import (
    ALL_RULES,
    IMPLEMENTED_RULES,
    PLANNED_RULES,
    detected_signals,
    run_rules,
)

LoadFixture = Callable[[str], NormalizedEmail]

# --------------------------------------------------------------------------
# The registry itself
# --------------------------------------------------------------------------


def test_each_signal_is_claimed_by_at_most_one_rule() -> None:
    signals = [rule.signal for rule in ALL_RULES]
    assert len(signals) == len(set(signals))


def test_every_phase_1_signal_has_a_rule() -> None:
    """The registry is the catalogue, so nothing may be missing from it."""
    phase1_signals = set(SpoofSignal) - PHASE2_SIGNALS
    assert {rule.signal for rule in ALL_RULES} == phase1_signals


def test_phase_2_signals_have_no_rule_yet() -> None:
    assert not {rule.signal for rule in ALL_RULES} & PHASE2_SIGNALS


def test_the_planned_rules_are_the_expected_two() -> None:
    assert {rule.signal for rule in PLANNED_RULES} == {
        SpoofSignal.EMBEDDED_QR,
        SpoofSignal.KNOWN_MALICIOUS,
    }


def test_implemented_and_planned_partition_all_rules() -> None:
    assert len(IMPLEMENTED_RULES) + len(PLANNED_RULES) == len(ALL_RULES)


@pytest.mark.parametrize("module", [embedded_qr, known_malicious])
def test_an_unfinished_rule_says_so_rather_than_returning_nothing(
    module: object, make_email: Callable[..., NormalizedEmail], context: RuleContext
) -> None:
    """Returning [] would quietly claim "no signal found"."""
    with pytest.raises(NotImplementedError):
        module.check(make_email(body_text="本文"), context)  # type: ignore[attr-defined]


def test_run_rules_skips_the_unfinished_rules(
    make_email: Callable[..., NormalizedEmail], context: RuleContext
) -> None:
    """If they were called, this would raise instead of returning findings."""
    email = make_email(
        sender_display_name="さくら銀行", sender_address="info@sakura-bamk.example"
    )
    assert run_rules(email, context) != []


def test_run_rules_builds_its_own_context_when_none_is_given(
    make_email: Callable[..., NormalizedEmail],
) -> None:
    email = make_email(sender_address="info@sakura-bamk.example")
    assert detected_signals(email) == [SpoofSignal.LOOKALIKE_DOMAIN]


# --------------------------------------------------------------------------
# End to end on the synthetic fixtures
# --------------------------------------------------------------------------


def test_a_legitimate_bank_notice_produces_no_signal(
    load_fixture_email: LoadFixture, context: RuleContext
) -> None:
    """The most important test in the project.

    Every ingredient here would trip a naive rule: the link text names the
    main domain while the anchor goes to the mail domain, the sender address
    is on a second domain, and the body carries images. All of it is
    legitimate, and the analysis must stay silent.
    """
    email = load_fixture_email("legit_bank_notice.json")
    findings = run_rules(email, context)
    assert findings == [], [finding.detail for finding in findings]


def test_a_phishing_alert_produces_the_expected_signals(
    load_fixture_email: LoadFixture, context: RuleContext
) -> None:
    email = load_fixture_email("phishing_bank_alert.json")
    assert detected_signals(email, context) == [
        SpoofSignal.DISPLAY_NAME_MISMATCH,
        SpoofSignal.LINK_MISMATCH,
        SpoofSignal.LOOKALIKE_DOMAIN,
        SpoofSignal.URL_SHORTENER,
        SpoofSignal.OPEN_REDIRECT,
        SpoofSignal.IP_ADDRESS_URL,
    ]


def test_every_finding_carries_evidence(
    load_fixture_email: LoadFixture, context: RuleContext
) -> None:
    """A label the user cannot be shown a reason for is not acceptable."""
    email = load_fixture_email("phishing_bank_alert.json")
    findings = run_rules(email, context)
    assert all(finding.quote for finding in findings)
    assert len(findings_to_evidence(findings)) == len(findings)


def test_signals_of_keeps_the_first_occurrence_order(
    load_fixture_email: LoadFixture, context: RuleContext
) -> None:
    email = load_fixture_email("phishing_bank_alert.json")
    findings = run_rules(email, context)
    assert signals_of(findings) == detected_signals(email, context)
