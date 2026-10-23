"""The shape of an axis 4 rule.

A rule is a plain function. It receives the email and a context holding the
reference data it may need, and returns a list of findings. Three consequences
of that choice:

- A rule performs no IO and reads no files, so a test can run it with a
  hand built context and no fixtures.
- A rule never decides a verdict. It reports what it saw; combining signals
  into a judgement happens elsewhere.
- Every finding carries the exact text that triggered it, because "show the
  evidence" is the point of the tool.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import lru_cache

from mekiki.email_input import NormalizedEmail
from mekiki.labels import Evidence, SpoofSignal
from mekiki.resources_io import load_domain_list
from mekiki.whitelist import Whitelist, load_whitelist

SHORTENER_RESOURCE = "shorteners.txt"


@lru_cache(maxsize=1)
def load_shorteners() -> frozenset[str]:
    """The packaged list of URL shortening service domains."""
    return load_domain_list(SHORTENER_RESOURCE)


@dataclass(frozen=True)
class RuleFinding:
    """One concrete observation made by a rule."""

    signal: SpoofSignal
    quote: str
    """The exact string from the email that triggered the finding, so the user
    can be shown why: a URL, a display name, a line of the body.

    One exception: a rule about something the email does *not* contain
    (``image_heavy_body``) has no string to point at, and gives a short
    measurement instead."""
    detail: str = ""
    """Short internal note on which branch of the rule fired. Not user facing;
    the wording shown to the user depends on the verdict."""


@dataclass(frozen=True)
class RuleContext:
    """Reference data handed to the rules.

    Passing this in rather than letting rules load it keeps them free of IO
    and makes test data trivial to substitute.
    """

    whitelist: Whitelist = field(default_factory=load_whitelist)
    shorteners: frozenset[str] = field(default_factory=load_shorteners)

    @classmethod
    def default(cls) -> RuleContext:
        """Context built from the packaged data files."""
        return cls(whitelist=load_whitelist(), shorteners=load_shorteners())


RuleCheck = Callable[[NormalizedEmail, RuleContext], list[RuleFinding]]


@dataclass(frozen=True)
class Rule:
    """A rule together with the signal it can produce."""

    signal: SpoofSignal
    check: RuleCheck
    implemented: bool = True
    """``False`` for rules that exist only as an interface so far. The registry
    skips them instead of calling them, so an unfinished rule cannot crash an
    analysis."""


def signals_of(findings: Iterable[RuleFinding]) -> list[SpoofSignal]:
    """Distinct signals from a list of findings, in order of first appearance.

    Several findings of the same kind (three IP address links, say) are one
    label on the email but stay separate pieces of evidence.
    """
    seen: set[SpoofSignal] = set()
    signals: list[SpoofSignal] = []
    for finding in findings:
        if finding.signal not in seen:
            seen.add(finding.signal)
            signals.append(finding.signal)
    return signals


def findings_to_evidence(findings: Iterable[RuleFinding]) -> list[Evidence]:
    """Convert findings into the evidence entries of an ``AnalysisResult``.

    Findings whose quote is empty are dropped: a label we cannot show a reason
    for is not worth presenting.
    """
    return [
        Evidence(label=finding.signal, quote=finding.quote)
        for finding in findings
        if finding.quote
    ]
