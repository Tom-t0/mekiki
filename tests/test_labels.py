"""Tests for the label system."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mekiki.labels import (
    ACTION_SEVERITY,
    PHASE2_SIGNALS,
    SENDER_CATEGORY_LABELS_JA,
    ActionSeverity,
    AdRisk,
    AnalysisResult,
    Confidence,
    Evidence,
    ExclusionReason,
    RequestedAction,
    SenderCategory,
    SpoofSignal,
    Tactic,
    Verdict,
    max_action_severity,
)

# --------------------------------------------------------------------------
# The tables must stay in sync with the enums
# --------------------------------------------------------------------------


def test_every_requested_action_has_a_severity() -> None:
    assert set(ACTION_SEVERITY) == set(RequestedAction)


def test_every_sender_category_has_a_japanese_label() -> None:
    assert set(SENDER_CATEGORY_LABELS_JA) == set(SenderCategory)


def test_label_values_do_not_collide_across_axes() -> None:
    """Evidence stores a label as a bare string, so the values must be unique."""
    values = (
        [tactic.value for tactic in Tactic]
        + [action.value for action in RequestedAction]
        + [signal.value for signal in SpoofSignal]
    )
    assert len(values) == len(set(values))


def test_phase2_signals_are_a_subset_of_all_signals() -> None:
    assert PHASE2_SIGNALS <= set(SpoofSignal)
    assert SpoofSignal.NEWLY_REGISTERED_DOMAIN in PHASE2_SIGNALS


# --------------------------------------------------------------------------
# Danger level is the maximum over the requested actions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        ([], None),
        ([RequestedAction.OPEN_LINK], ActionSeverity.MEDIUM),
        ([RequestedAction.OPEN_LINK, RequestedAction.REPLY], ActionSeverity.MEDIUM),
        (
            [RequestedAction.OPEN_LINK, RequestedAction.ENTER_CREDENTIALS],
            ActionSeverity.HIGH,
        ),
        (
            [RequestedAction.ENTER_CREDENTIALS, RequestedAction.SEND_MONEY],
            ActionSeverity.CRITICAL,
        ),
        # Order must not matter: the maximum is taken, not the last value.
        (
            [RequestedAction.SEND_MONEY, RequestedAction.OPEN_LINK],
            ActionSeverity.CRITICAL,
        ),
    ],
)
def test_max_action_severity(
    actions: list[RequestedAction], expected: ActionSeverity | None
) -> None:
    assert max_action_severity(actions) == expected


def test_danger_level_property_matches_the_helper() -> None:
    result = AnalysisResult(
        verdict=Verdict.SCAM,
        confidence=Confidence.HIGH,
        requested_actions=[RequestedAction.OPEN_LINK, RequestedAction.SEND_MONEY],
    )
    assert result.danger_level is ActionSeverity.CRITICAL


# --------------------------------------------------------------------------
# A verdict carries exactly one piece of extra information
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"verdict": "scam", "confidence": "high"},
        {"verdict": "legit", "confidence": "low"},
        {"verdict": "ad", "ad_risk": "high"},
        {"verdict": "undeterminable", "exclusion_reason": "missing_content"},
        {"verdict": "undeterminable", "exclusion_reason": "unsupported_format"},
    ],
)
def test_valid_verdict_combinations(payload: dict[str, str]) -> None:
    result = AnalysisResult.model_validate(payload)
    assert result.verdict.value == payload["verdict"]


@pytest.mark.parametrize(
    "payload",
    [
        # Required field missing.
        {"verdict": "scam"},
        {"verdict": "legit"},
        {"verdict": "ad"},
        {"verdict": "undeterminable"},
        # A field belonging to another verdict is set.
        {"verdict": "scam", "confidence": "high", "ad_risk": "low"},
        {"verdict": "ad", "ad_risk": "low", "confidence": "high"},
        {"verdict": "legit", "confidence": "high", "exclusion_reason": "missing_content"},
        {"verdict": "undeterminable", "exclusion_reason": "missing_content", "confidence": "low"},
        # The wrong field alone is not enough.
        {"verdict": "scam", "ad_risk": "high"},
    ],
)
def test_invalid_verdict_combinations(payload: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)


def test_unknown_field_is_rejected() -> None:
    """Guards against silent typos in JSON coming from the extension or an LLM."""
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(
            {"verdict": "scam", "confidence": "high", "confidance": "low"}
        )


def test_unknown_enum_value_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({"verdict": "phishing", "confidence": "high"})


# --------------------------------------------------------------------------
# Axes and evidence
# --------------------------------------------------------------------------


def test_legitimate_mail_can_carry_axis_1_to_3() -> None:
    """A real bank notice also has a claimed sender, a tone and an action."""
    result = AnalysisResult(
        verdict=Verdict.LEGIT,
        confidence=Confidence.HIGH,
        claimed_entity="さくら銀行",
        sender_category=SenderCategory.BANK,
        tactics=[Tactic.ROUTINE_PROCEDURE],
        requested_actions=[RequestedAction.OPEN_LINK],
    )
    assert result.sender_category is SenderCategory.BANK
    assert result.danger_level is ActionSeverity.MEDIUM


def test_duplicate_labels_are_dropped_but_order_is_kept() -> None:
    result = AnalysisResult(
        verdict=Verdict.SCAM,
        confidence=Confidence.LOW,
        tactics=[Tactic.URGENCY, Tactic.AUTHORITY, Tactic.URGENCY],
    )
    assert result.tactics == [Tactic.URGENCY, Tactic.AUTHORITY]


def test_evidence_accepts_labels_from_every_axis() -> None:
    result = AnalysisResult(
        verdict=Verdict.SCAM,
        confidence=Confidence.HIGH,
        tactics=[Tactic.URGENCY],
        requested_actions=[RequestedAction.ENTER_CREDENTIALS],
        spoof_signals=[SpoofSignal.LINK_MISMATCH],
        evidence=[
            Evidence(label=Tactic.URGENCY, quote="24時間以内にご対応ください"),
            Evidence(label=RequestedAction.ENTER_CREDENTIALS, quote="暗証番号をご入力"),
            Evidence(label=SpoofSignal.LINK_MISMATCH, quote="sakura-bamk.example"),
        ],
    )
    assert [item.label for item in result.evidence] == [
        Tactic.URGENCY,
        RequestedAction.ENTER_CREDENTIALS,
        SpoofSignal.LINK_MISMATCH,
    ]


def test_evidence_label_is_parsed_into_the_right_enum() -> None:
    evidence = Evidence.model_validate({"label": "urgency", "quote": "本日中に"})
    assert evidence.label is Tactic.URGENCY


def test_evidence_for_an_unassigned_label_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisResult(
            verdict=Verdict.SCAM,
            confidence=Confidence.HIGH,
            tactics=[Tactic.URGENCY],
            evidence=[Evidence(label=Tactic.AUTHORITY, quote="当行の規定により")],
        )


def test_evidence_quote_must_not_be_empty() -> None:
    with pytest.raises(ValidationError):
        Evidence(label=Tactic.URGENCY, quote="")


# --------------------------------------------------------------------------
# JSON round trip, because this crosses the process boundary
# --------------------------------------------------------------------------


def test_json_round_trip() -> None:
    original = AnalysisResult(
        verdict=Verdict.AD,
        ad_risk=AdRisk.HIGH,
        claimed_entity="ハルカ証券",
        sender_category=SenderCategory.SECURITIES,
        tactics=[Tactic.GAIN_OFFER],
        requested_actions=[RequestedAction.OPEN_LINK],
        evidence=[Evidence(label=Tactic.GAIN_OFFER, quote="年利20%を保証")],
    )
    restored = AnalysisResult.model_validate_json(original.model_dump_json())
    assert restored == original


def test_exclusion_reason_round_trip() -> None:
    result = AnalysisResult.model_validate(
        {"verdict": "undeterminable", "exclusion_reason": "unsupported_format"}
    )
    assert result.exclusion_reason is ExclusionReason.UNSUPPORTED_FORMAT
    assert result.danger_level is None
