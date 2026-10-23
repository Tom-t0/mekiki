"""The normalized input an analysis works on.

Everything upstream of this module (phase 1: a Chrome extension reading the
Gmail screen) has one job: produce a ``NormalizedEmail``. Nothing downstream
needs to know where the data came from, so the extraction code can be replaced
without touching the rules.

Headers are deliberately absent: phase 1 does not use them.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _blank_to_none(value: str | None) -> str | None:
    """Treat whitespace only text as missing.

    Screen scraping yields ``""`` rather than nothing at all, and an empty
    string would otherwise look like a real value such as an empty display
    name.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


class EmailLink(BaseModel):
    """One hyperlink in the body.

    The pair of "what the reader sees" and "where it actually goes" is what
    makes ``link_mismatch`` detectable, so both are kept verbatim.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    display_text: str = ""
    href: str

    @field_validator("display_text", mode="before")
    @classmethod
    def _normalize_display_text(cls, value: str | None) -> str:
        return "" if value is None else str(value).strip()

    @field_validator("href", mode="before")
    @classmethod
    def _strip_href(cls, value: str) -> str:
        return str(value).strip()


class NormalizedEmail(BaseModel):
    """An email reduced to the fields the analysis actually uses.

    The model is frozen so that a rule cannot accidentally modify the email it
    is judging. (Frozen blocks attribute assignment; the list fields are still
    ordinary lists, so rules must not mutate them either.)
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sender_display_name: str | None = None
    sender_address: str | None = None
    subject: str | None = None
    body_text: str = ""
    body_html: str | None = None
    links: list[EmailLink] = Field(default_factory=list)
    image_count: int = Field(default=0, ge=0)

    @field_validator("sender_display_name", "subject", "body_html", mode="before")
    @classmethod
    def _normalize_optional_text(cls, value: str | None) -> str | None:
        return _blank_to_none(value)

    @field_validator("sender_address", mode="before")
    @classmethod
    def _normalize_address(cls, value: str | None) -> str | None:
        """Lower case the domain part only.

        Domains are case insensitive, so comparing them requires one casing.
        The local part is case sensitive per RFC 5321 and is left alone.
        """
        address = _blank_to_none(value)
        if address is None or "@" not in address:
            return address
        local_part, _, domain = address.rpartition("@")
        return f"{local_part}@{domain.lower()}"

    @field_validator("body_text", mode="before")
    @classmethod
    def _normalize_body_text(cls, value: str | None) -> str:
        """Make whitespace comparable across sources.

        A body lifted out of HTML is full of CRLF and non breaking spaces;
        leaving them in would make text length and quoting unreliable.
        """
        if value is None:
            return ""
        return str(value).replace("\r\n", "\n").replace("\r", "\n").replace(" ", " ")

    @property
    def text_length(self) -> int:
        """Length of the visible text, ignoring surrounding whitespace."""
        return len(self.body_text.strip())

    def has_analyzable_content(self) -> bool:
        """Whether there is anything at all to judge.

        A ``False`` here is what justifies the verdict ``undeterminable`` with
        ``exclusion_reason = missing_content``: the data is missing, which is
        not the same as the email being harmless.
        """
        return bool(
            self.body_text.strip()
            or self.body_html
            or self.links
            or self.image_count > 0
        )
