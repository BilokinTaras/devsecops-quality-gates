"""Baseline of accepted findings.

Each entry must say why the finding is accepted, who owns the decision and when the
acceptance expires. Expired entries stop suppressing their finding, so risk acceptance
is revisited instead of living forever.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import Finding

_PLACEHOLDERS = {"", "todo", "tbd", "n/a", "-"}


class BaselineError(ValueError):
    """The baseline file is malformed."""


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    tool: str
    rule_id: str
    location: str
    reason: str
    owner: str
    expires: dt.date

    def is_expired(self, today: dt.date) -> bool:
        return self.expires < today

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "location": self.location,
            "reason": self.reason,
            "owner": self.owner,
            "expires": self.expires.isoformat(),
        }


def _required_text(raw: dict[str, Any], key: str, index: int) -> str:
    value = str(raw.get(key, "")).strip()
    if value.lower() in _PLACEHOLDERS:
        raise BaselineError(f"baseline entry #{index}: '{key}' must be filled in (got {value!r})")
    return value


def _parse_date(value: Any, index: int) -> dt.date:
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        raise BaselineError(
            f"baseline entry #{index}: 'expires' must be YYYY-MM-DD (got {value!r})"
        ) from None


def load_baseline(path: Path | None) -> list[BaselineEntry]:
    if path is None or not path.exists():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise BaselineError("baseline must be a mapping with 'version: 1'")
    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    for index, raw in enumerate(doc.get("entries") or [], start=1):
        if not isinstance(raw, dict):
            raise BaselineError(f"baseline entry #{index} must be a mapping")
        entry = BaselineEntry(
            fingerprint=_required_text(raw, "fingerprint", index),
            tool=_required_text(raw, "tool", index),
            rule_id=_required_text(raw, "rule_id", index),
            location=str(raw.get("location", "")),
            reason=_required_text(raw, "reason", index),
            owner=_required_text(raw, "owner", index),
            expires=_parse_date(raw.get("expires"), index),
        )
        if entry.fingerprint in seen:
            raise BaselineError(f"baseline entry #{index}: duplicate fingerprint {entry.fingerprint}")
        seen.add(entry.fingerprint)
        entries.append(entry)
    return entries


def draft_entries(findings: list[Finding], owner: str, today: dt.date, days: int = 90) -> dict[str, Any]:
    """A baseline draft for triage. Reasons are left as TODO on purpose: the gate rejects them until filled."""
    unique = {f.fingerprint: f for f in findings}
    return {
        "version": 1,
        "entries": [
            {
                "fingerprint": f.fingerprint,
                "tool": f.tool,
                "rule_id": f.rule_id,
                "location": f.location,
                "severity": f.severity.label,
                "reason": "TODO",
                "owner": owner,
                "expires": (today + dt.timedelta(days=days)).isoformat(),
            }
            for f in sorted(unique.values(), key=lambda f: (-f.severity, f.tool, f.rule_id, f.location))
        ],
    }
