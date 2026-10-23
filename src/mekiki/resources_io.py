"""Reading the data files shipped inside the package.

Kept separate from the modules that use the data so that the "where does this
file live" question is answered in exactly one place. ``importlib.resources``
is used rather than ``__file__`` arithmetic, so the files are still found when
the package is installed as a zip or a wheel.

Note the two different data directories in this project:

- ``src/mekiki/resources/`` (here) holds dictionaries that are part of the
  program and are committed.
- ``data/`` at the repository root holds collected email data and is never
  committed.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

_RESOURCE_DIRECTORY = "resources"


def resource_text(name: str) -> str:
    """Contents of a packaged resource file."""
    return (
        files("mekiki").joinpath(_RESOURCE_DIRECTORY).joinpath(name).read_text("utf-8")
    )


def resource_json(name: str) -> Any:
    """Parsed contents of a packaged JSON resource."""
    return json.loads(resource_text(name))


def load_domain_list(name: str) -> frozenset[str]:
    """A plain text list of domains, one per line.

    ``#`` introduces a comment and blank lines are skipped, so the list can be
    annotated without a second format.
    """
    domains: set[str] = set()
    for raw_line in resource_text(name).splitlines():
        line = raw_line.split("#", 1)[0].strip().lower()
        if line:
            domains.add(line)
    return frozenset(domains)
