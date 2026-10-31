from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """CVSS v3 qualitative rating scale."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: Severity
    title: str
    location: str
    source: str
    cwe: tuple[str, ...] = field(default_factory=tuple)
    fingerprint_hint: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable ID used by the baseline. Prefers the tool's own fingerprint when it has one."""
        basis = self.fingerprint_hint or self.location
        raw = f"{self.tool.lower()}|{self.rule_id}|{basis}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["cwe"] = list(self.cwe)
        data["fingerprint"] = self.fingerprint
        del data["fingerprint_hint"]
        return data
