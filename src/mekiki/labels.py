"""The label system of Mekiki.

Four axes plus one top level verdict. See CLAUDE.md section 5 for the
authoritative specification; this module is its executable form.

Design notes:
- Label names are kept neutral (``open_link``, not ``malicious_link``) because
  the same label is attached to legitimate mail as well. How a label is worded
  for the user depends on the verdict and is a presentation concern, handled
  outside this module.
- ``ActionSeverity`` is an ``IntEnum`` so that the danger level of a whole
  email is simply ``max()`` over its requested actions. The trade-off is that
  it serializes to a number; acceptable because the severity is fixed per
  action label and is never supplied by an external component.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# --------------------------------------------------------------------------
# Top level verdict
# --------------------------------------------------------------------------


class Verdict(str, Enum):
    """The single top level judgement of an email."""

    SCAM = "scam"
    LEGIT = "legit"
    AD = "ad"
    UNDETERMINABLE = "undeterminable"


class Confidence(str, Enum):
    """Confidence attached to ``scam`` and ``legit``."""

    HIGH = "high"
    LOW = "low"


class AdRisk(str, Enum):
    """Risk level attached to ``ad``.

    ``HIGH`` applies when any of the following is present: a large payment or
    contract, an investment hinting at guaranteed principal or high yield, a
    subscription with unclear cancellation terms, exaggerated claims asserting
    income or health effects, or a request for unnecessary personal data.
    """

    HIGH = "high"
    LOW = "low"


class ExclusionReason(str, Enum):
    """Why an email could not be judged at all."""

    MISSING_CONTENT = "missing_content"
    UNSUPPORTED_FORMAT = "unsupported_format"


# --------------------------------------------------------------------------
# Axis 1: the sender the email claims to be (internal data, never displayed)
# --------------------------------------------------------------------------


class SenderCategory(str, Enum):
    """Category derived from the claimed entity through a lookup table."""

    BANK = "bank"
    CARD = "card"
    SECURITIES = "securities"
    ECOMMERCE = "ecommerce"
    PAYMENT = "payment"
    DELIVERY = "delivery"
    TELECOM_IT = "telecom_it"
    UTILITY = "utility"
    PUBLIC_AGENCY = "public_agency"
    OTHER = "other"


SENDER_CATEGORY_LABELS_JA: dict[SenderCategory, str] = {
    SenderCategory.BANK: "銀行",
    SenderCategory.CARD: "カード会社",
    SenderCategory.SECURITIES: "証券・投資",
    SenderCategory.ECOMMERCE: "通販・EC",
    SenderCategory.PAYMENT: "決済・ポイント",
    SenderCategory.DELIVERY: "配送",
    SenderCategory.TELECOM_IT: "通信・IT",
    SenderCategory.UTILITY: "公共料金・インフラ",
    SenderCategory.PUBLIC_AGENCY: "公的機関",
    SenderCategory.OTHER: "なし・その他",
}


# --------------------------------------------------------------------------
# Axis 2: persuasion tactics (multiple allowed)
# --------------------------------------------------------------------------


class Tactic(str, Enum):
    """How the email tries to persuade the reader."""

    AUTHORITY = "authority"
    URGENCY = "urgency"
    LOSS_THREAT = "loss_threat"
    GAIN_OFFER = "gain_offer"
    CURIOSITY = "curiosity"
    ROUTINE_PROCEDURE = "routine_procedure"


# --------------------------------------------------------------------------
# Axis 3: requested actions (multiple allowed, fixed severity per label)
# --------------------------------------------------------------------------


class ActionSeverity(IntEnum):
    """Danger level of a requested action. Higher is more dangerous."""

    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class RequestedAction(str, Enum):
    """What the email asks the reader to do."""

    OPEN_LINK = "open_link"
    SCAN_QR = "scan_qr"
    REPLY = "reply"
    OPEN_ATTACHMENT = "open_attachment"
    ENTER_CREDENTIALS = "enter_credentials"
    CALL_PHONE = "call_phone"
    ENTER_PAYMENT_INFO = "enter_payment_info"
    SEND_MONEY = "send_money"
    INSTALL_APP = "install_app"


ACTION_SEVERITY: dict[RequestedAction, ActionSeverity] = {
    RequestedAction.OPEN_LINK: ActionSeverity.MEDIUM,
    RequestedAction.SCAN_QR: ActionSeverity.MEDIUM,
    RequestedAction.REPLY: ActionSeverity.MEDIUM,
    RequestedAction.OPEN_ATTACHMENT: ActionSeverity.HIGH,
    RequestedAction.ENTER_CREDENTIALS: ActionSeverity.HIGH,
    RequestedAction.CALL_PHONE: ActionSeverity.HIGH,
    RequestedAction.ENTER_PAYMENT_INFO: ActionSeverity.CRITICAL,
    RequestedAction.SEND_MONEY: ActionSeverity.CRITICAL,
    RequestedAction.INSTALL_APP: ActionSeverity.CRITICAL,
}


def max_action_severity(actions: list[RequestedAction]) -> ActionSeverity | None:
    """Danger level of an email: the maximum over its requested actions."""
    if not actions:
        return None
    return max(ACTION_SEVERITY[action] for action in actions)


# --------------------------------------------------------------------------
# Axis 4: technical spoofing signals (decided by rules)
# --------------------------------------------------------------------------


class SpoofSignal(str, Enum):
    """Technical signs of impersonation, detected mechanically."""

    DISPLAY_NAME_MISMATCH = "display_name_mismatch"
    LINK_MISMATCH = "link_mismatch"
    LOOKALIKE_DOMAIN = "lookalike_domain"
    URL_SHORTENER = "url_shortener"
    OPEN_REDIRECT = "open_redirect"
    IP_ADDRESS_URL = "ip_address_url"
    IMAGE_HEAVY_BODY = "image_heavy_body"
    EMBEDDED_QR = "embedded_qr"
    KNOWN_MALICIOUS = "known_malicious"
    NEWLY_REGISTERED_DOMAIN = "newly_registered_domain"


PHASE2_SIGNALS: frozenset[SpoofSignal] = frozenset(
    {SpoofSignal.NEWLY_REGISTERED_DOMAIN}
)
"""Signals that need data we deliberately do not collect in phase 1."""


# --------------------------------------------------------------------------
# Evidence and the assembled result
# --------------------------------------------------------------------------

LabelRef = Tactic | RequestedAction | SpoofSignal
"""Any label that can be backed by evidence.

The three enums share no values, so Pydantic can tell them apart when parsing
JSON.
"""


class Evidence(BaseModel):
    """The excerpt of the email that justifies one label.

    Showing the evidence is the point of the whole tool, so a label without a
    quote from the email is not acceptable output.
    """

    model_config = ConfigDict(extra="forbid")

    label: LabelRef
    quote: str = Field(min_length=1)


T = TypeVar("T")


def _dedupe(values: list[T]) -> list[T]:
    """Drop duplicates while keeping the original order."""
    seen: set[T] = set()
    unique: list[T] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


_VERDICT_REQUIRED_FIELD: dict[Verdict, str] = {
    Verdict.SCAM: "confidence",
    Verdict.LEGIT: "confidence",
    Verdict.AD: "ad_risk",
    Verdict.UNDETERMINABLE: "exclusion_reason",
}

_VERDICT_DEPENDENT_FIELDS = ("confidence", "ad_risk", "exclusion_reason")


class AnalysisResult(BaseModel):
    """The complete labelling of one email.

    Axes 1 to 3 are filled in for legitimate mail too: a real bank notice also
    has a claimed sender, a tone and a requested action.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: Confidence | None = None
    ad_risk: AdRisk | None = None
    exclusion_reason: ExclusionReason | None = None

    # Axis 1 (internal only, never shown to the user).
    claimed_entity: str | None = None
    sender_category: SenderCategory | None = None

    # Axes 2 to 4.
    tactics: list[Tactic] = Field(default_factory=list)
    requested_actions: list[RequestedAction] = Field(default_factory=list)
    spoof_signals: list[SpoofSignal] = Field(default_factory=list)

    evidence: list[Evidence] = Field(default_factory=list)

    @field_validator("tactics", "requested_actions", "spoof_signals")
    @classmethod
    def _drop_duplicate_labels(cls, value: list[T]) -> list[T]:
        return _dedupe(value)

    @model_validator(mode="after")
    def _check_verdict_dependent_fields(self) -> AnalysisResult:
        """Each verdict carries exactly one piece of extra information."""
        required = _VERDICT_REQUIRED_FIELD[self.verdict]
        if getattr(self, required) is None:
            raise ValueError(f"verdict '{self.verdict.value}' requires '{required}'")
        for name in _VERDICT_DEPENDENT_FIELDS:
            if name != required and getattr(self, name) is not None:
                raise ValueError(f"verdict '{self.verdict.value}' must not set '{name}'")
        return self

    @model_validator(mode="after")
    def _check_evidence_points_at_assigned_labels(self) -> AnalysisResult:
        """Evidence may only back a label that was actually assigned.

        This is the machine checkable half of "only attach a label when the
        body supports it".
        """
        assigned: set[LabelRef] = {
            *self.tactics,
            *self.requested_actions,
            *self.spoof_signals,
        }
        for item in self.evidence:
            if item.label not in assigned:
                raise ValueError(
                    f"evidence refers to unassigned label '{item.label.value}'"
                )
        return self

    @property
    def danger_level(self) -> ActionSeverity | None:
        """Danger level of this email, or ``None`` if nothing is requested."""
        return max_action_severity(self.requested_actions)
