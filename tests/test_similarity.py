"""Tests for the hand written similarity helpers."""

from __future__ import annotations

import pytest

from mekiki.similarity import levenshtein, normalize_confusables

# --------------------------------------------------------------------------
# levenshtein
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("", "", 0),
        ("abc", "abc", 0),
        ("", "abc", 3),
        ("abc", "", 3),
        # One substitution.
        ("sakura-bank", "sakura-bamk", 1),
        # One deletion.
        ("sakura-bank", "sakurabank", 1),
        # One insertion.
        ("sakura-bank", "sakura-bannk", 1),
        # A transposition costs two edits with this metric, which is why the
        # rule's threshold cannot be 1 if it wants to catch swapped letters.
        ("sakura-bank", "sakura-bnak", 2),
        ("kitten", "sitting", 3),
        ("日本語", "日本後", 1),
    ],
)
def test_levenshtein(left: str, right: str, expected: int) -> None:
    assert levenshtein(left, right) == expected


@pytest.mark.parametrize(
    ("left", "right"),
    [("sakura-bank", "sakura-bamk"), ("kitten", "sitting"), ("", "abc")],
)
def test_levenshtein_is_symmetric(left: str, right: str) -> None:
    assert levenshtein(left, right) == levenshtein(right, left)


# --------------------------------------------------------------------------
# normalize_confusables
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # rn drawn as m, the single most common domain trick.
        ("rnidori-card.example", "midori-card.example"),
        ("vvatch.example", "watch.example"),
        # Digits used as letters.
        ("s0rapay.example", "sorapay.example"),
        ("haruka-sec1.example", "haruka-secl.example"),
        # Cyrillic homographs.
        ("sаkura-bаnk.example", "sakura-bank.example"),
        # Full width characters are folded by NFKC.
        ("ＳＡＫＵＲＡ.example", "sakura.example"),
        # Case folding.
        ("Sakura-Bank.Example", "sakura-bank.example"),
        # Already plain text is unchanged.
        ("sakura-bank.example", "sakura-bank.example"),
    ],
)
def test_normalize_confusables(text: str, expected: str) -> None:
    assert normalize_confusables(text) == expected


def test_multi_character_sequences_are_applied_before_single_characters() -> None:
    """If "r" or "n" were replaced first, "rn" would never be seen."""
    assert normalize_confusables("rnrn") == "mm"
