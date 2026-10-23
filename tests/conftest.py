"""Shared fixtures for the rule tests.

The helpers exist so that each test states only the part of the email it cares
about; everything else stays at its default.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mekiki.email_input import EmailLink, NormalizedEmail
from mekiki.rules.base import RuleContext

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "emails"


@pytest.fixture
def context() -> RuleContext:
    """Rule context built from the packaged data files."""
    return RuleContext.default()


@pytest.fixture
def make_email() -> Callable[..., NormalizedEmail]:
    """Factory for a normalized email with only the stated fields set."""

    def factory(**fields: Any) -> NormalizedEmail:
        return NormalizedEmail(**fields)

    return factory


@pytest.fixture
def make_link() -> Callable[..., EmailLink]:
    """Factory for one link. ``display_text`` defaults to empty."""

    def factory(href: str, display_text: str = "") -> EmailLink:
        return EmailLink(href=href, display_text=display_text)

    return factory


@pytest.fixture
def load_fixture_email() -> Callable[[str], NormalizedEmail]:
    """Load one of the synthetic emails in ``tests/fixtures/emails``.

    These files are the only email data in the repository and are entirely
    made up, with domains in the reserved ``.example`` namespace.
    """

    def loader(name: str) -> NormalizedEmail:
        path = FIXTURE_DIRECTORY / name
        return NormalizedEmail.model_validate(json.loads(path.read_text("utf-8")))

    return loader
