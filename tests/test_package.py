"""Smoke test: the package under src/ is importable from the test suite."""

import mekiki


def test_version_is_exposed() -> None:
    assert mekiki.__version__ == "0.1.0"
