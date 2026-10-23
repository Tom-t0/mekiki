"""Text similarity used by the lookalike domain rule.

Both functions are written out by hand rather than pulled from a library. The
lookalike rule is the one place where the tool makes a judgement call about how
close is "too close", so the arithmetic behind it has to be inspectable.
"""

from __future__ import annotations

import unicodedata

CONFUSABLE_SEQUENCES: tuple[tuple[str, str], ...] = (
    # Multi character shapes, applied before single characters so that "rn"
    # is not broken up by an earlier substitution.
    ("rn", "m"),
    ("vv", "w"),
)

CONFUSABLE_CHARACTERS: dict[str, str] = {
    # Digits used as letters.
    "0": "o",
    "1": "l",
    "|": "l",
    # Latin lookalikes.
    "ı": "i",
    # Cyrillic letters that are drawn like Latin ones. This is the classic
    # homograph attack: "раураl" is not "paypal".
    "а": "a",
    "в": "b",
    "е": "e",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    # Greek.
    "ο": "o",
    "α": "a",
    "ν": "v",
    "ρ": "p",
    "τ": "t",
}


def normalize_confusables(text: str) -> str:
    """Fold characters that are drawn alike onto one spelling.

    NFKC first, which collapses full width forms (``ｓａｋｕｒａ`` becomes
    ``sakura``), then the explicit table above.
    """
    folded = unicodedata.normalize("NFKC", text).casefold()
    for sequence, replacement in CONFUSABLE_SEQUENCES:
        folded = folded.replace(sequence, replacement)
    return "".join(CONFUSABLE_CHARACTERS.get(character, character) for character in folded)


def levenshtein(left: str, right: str) -> int:
    """Edit distance: the number of insertions, deletions or substitutions.

    Two rows of the dynamic programming table are enough, since each row only
    depends on the one above it.
    """
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous_row = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current_row = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            deletion = previous_row[right_index] + 1
            insertion = current_row[right_index - 1] + 1
            substitution = previous_row[right_index - 1] + (
                left_character != right_character
            )
            current_row.append(min(deletion, insertion, substitution))
        previous_row = current_row
    return previous_row[-1]
