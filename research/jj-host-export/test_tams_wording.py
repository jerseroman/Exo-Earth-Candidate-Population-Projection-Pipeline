#!/usr/bin/env python3
"""Regression guard for the non-directional TAMS metallicity limitation."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    ROOT / ".github" / "workflows" / "jj-g-host-export.yml",
    ROOT / "research" / "jj-host-export" / "promote_tams_provider.py",
)
FORBIDDEN = (
    "may therefore be permissive",
    "may be permissive",
    "can have a smaller TAMS radius",
)
REQUIRED = (
    "unquantified host-selection systematic",
    "neither the sign nor the magnitude",
)


class TamsWordingTests(unittest.TestCase):
    def test_active_tams_limitations_are_non_directional(self) -> None:
        for path in TARGETS:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            for phrase in FORBIDDEN:
                self.assertNotIn(phrase.lower(), lowered, path.as_posix())
            for phrase in REQUIRED:
                self.assertIn(phrase.lower(), lowered, path.as_posix())


if __name__ == "__main__":
    unittest.main()
