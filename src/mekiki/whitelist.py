"""Known organizations and the domains they legitimately send from.

WHAT THIS IS FOR
    Keeping the axis 4 rules from firing on genuine corporate mail. A bank
    that sends from ``sakura-bank-mail.example`` while writing
    ``sakura-bank.example`` in its link text is not spoofing anything, and
    without this table ``link_mismatch`` would say it is.

WHAT THIS IS NOT FOR
    Deciding that an email is safe. Phishing is sent from legitimate domains
    too (compromised accounts, hijacked marketing tools), so a match here says
    nothing about intent. No code in this project may turn a whitelist hit
    into a ``legit`` verdict.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

from pydantic import BaseModel, ConfigDict, Field

from mekiki.labels import SenderCategory
from mekiki.resources_io import resource_json
from mekiki.urls import is_subdomain_of

WHITELIST_RESOURCE = "whitelist.json"
SENDER_CATEGORY_RESOURCE = "sender_categories.json"

_DECORATION_CHARACTERS = "【】[]()（）<>《》「」『』〈〉"


def normalize_entity_name(text: str) -> str:
    """Fold an organization name so that written variants compare equal.

    Display names in the wild are decorated: "【さくら銀行】", "さくら銀行
    カスタマーセンター", full width Latin. NFKC plus dropping whitespace and
    bracket characters makes those comparable without a per sender rule.
    """
    folded = unicodedata.normalize("NFKC", text).casefold()
    return "".join(
        character
        for character in folded
        if not character.isspace() and character not in _DECORATION_CHARACTERS
    )


class WhitelistEntry(BaseModel):
    """One organization and the domains it is known to send from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity: str
    aliases: list[str] = Field(default_factory=list)
    domains: list[str] = Field(min_length=1)

    @property
    def names(self) -> list[str]:
        """The canonical name together with every alias."""
        return [self.entity, *self.aliases]

    def owns_host(self, host: str | None) -> bool:
        """Whether a host belongs to this organization.

        Subdomains count: ``mail.sakura-bank.example`` is still the bank.
        """
        return any(is_subdomain_of(host, domain) for domain in self.domains)

    def is_claimed_in(self, text: str | None) -> bool:
        """Whether ``text`` claims to be this organization.

        Containment rather than equality, because a display name is usually
        the organization plus a department.
        """
        if not text:
            return False
        normalized_text = normalize_entity_name(text)
        if not normalized_text:
            return False
        return any(
            normalize_entity_name(name) in normalized_text
            for name in self.names
            if normalize_entity_name(name)
        )


class Whitelist(BaseModel):
    """The whole table, loaded from ``whitelist.json``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    entries: list[WhitelistEntry] = Field(default_factory=list)
    note: str | None = None

    @property
    def all_domains(self) -> tuple[str, ...]:
        """Every legitimate domain, in file order."""
        return tuple(domain for entry in self.entries for domain in entry.domains)

    def entry_for_host(self, host: str | None) -> WhitelistEntry | None:
        """The organization that owns ``host``, if it is known."""
        if not host:
            return None
        for entry in self.entries:
            if entry.owns_host(host):
                return entry
        return None

    def knows_host(self, host: str | None) -> bool:
        """Whether the host is a known legitimate domain (or a subdomain)."""
        return self.entry_for_host(host) is not None

    def entry_claimed_in(self, text: str | None) -> WhitelistEntry | None:
        """The organization a display name or subject claims to be.

        The longest name wins, so that an entry whose name contains another
        entry's name is not shadowed by it.
        """
        if not text:
            return None
        matches = [entry for entry in self.entries if entry.is_claimed_in(text)]
        if not matches:
            return None
        return max(matches, key=lambda entry: len(normalize_entity_name(entry.entity)))

    def entry_for_entity(self, entity: str | None) -> WhitelistEntry | None:
        """Look an organization up by its canonical name or an alias."""
        if not entity:
            return None
        normalized = normalize_entity_name(entity)
        for entry in self.entries:
            if any(normalize_entity_name(name) == normalized for name in entry.names):
                return entry
        return None


class SenderCategoryTable(BaseModel):
    """Axis 1: claimed entity to sender category."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    categories: dict[str, SenderCategory] = Field(default_factory=dict)
    note: str | None = None

    def category_for(self, entity: str | None) -> SenderCategory:
        """Category of an organization.

        Unknown names fall back to ``other`` rather than raising: an unlisted
        sender is a normal situation, not an error.
        """
        if not entity:
            return SenderCategory.OTHER
        normalized = normalize_entity_name(entity)
        for name, category in self.categories.items():
            if normalize_entity_name(name) == normalized:
                return category
        return SenderCategory.OTHER


@lru_cache(maxsize=1)
def load_whitelist() -> Whitelist:
    """The packaged whitelist, parsed once."""
    return Whitelist.model_validate(resource_json(WHITELIST_RESOURCE))


@lru_cache(maxsize=1)
def load_sender_categories() -> SenderCategoryTable:
    """The packaged entity to category table, parsed once."""
    return SenderCategoryTable.model_validate(resource_json(SENDER_CATEGORY_RESOURCE))


def sender_category_for_display_name(display_name: str | None) -> SenderCategory:
    """Axis 1 end to end: display name to claimed entity to category.

    Convenience for the labelling tool. Returns ``other`` when the display
    name does not claim any known organization.
    """
    entry = load_whitelist().entry_claimed_in(display_name)
    if entry is None:
        return SenderCategory.OTHER
    return load_sender_categories().category_for(entry.entity)
