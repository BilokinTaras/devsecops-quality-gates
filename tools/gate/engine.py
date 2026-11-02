"""Gate decision and reports."""

from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .baseline import BaselineEntry
from .models import Finding, Severity


@dataclass
class GateResult:
    threshold: Severity
    inputs: list[str]
    findings: list[Finding]
    blocking: list[Finding] = field(default_factory=list)
    non_blocking: list[Finding] = field(default_factory=list)
    suppressed: list[tuple[Finding, BaselineEntry]] = field(default_factory=list)
    expired: list[BaselineEntry] = field(default_factory=list)
    stale: list[BaselineEntry] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.blocking

    def to_dict(self, generated_at: str) -> dict[str, Any]:
        by_sev = Counter(f.severity.label for f in self.findings)
        by_tool = Counter(f.tool for f in self.findings)
        return {
            "status": "pass" if self.passed else "fail",
            "generated_at": generated_at,
            "threshold": self.threshold.label,
            "inputs": self.inputs,
            "totals": {
                "findings": len(self.findings),
                "by_severity": {s.label: by_sev.get(s.label, 0) for s in reversed(Severity)},
                "by_tool": dict(sorted(by_tool.items())),
                "blocking": len(self.blocking),
                "non_blocking": len(self.non_blocking),
                "suppressed": len(self.suppressed),
                "expired_baseline": len(self.expired),
                "stale_baseline": len(self.stale),
            },
            "blocking": [f.to_dict() for f in self.blocking],
            "non_blocking": [f.to_dict() for f in self.non_blocking],
            "suppressed": [{**f.to_dict(), "baseline": e.to_dict()} for f, e in self.suppressed],
            "expired_baseline": [e.to_dict() for e in self.expired],
            "stale_baseline": [e.to_dict() for e in self.stale],
        }


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Same tool + fingerprint reported twice (e.g. SARIF and JSON of one scan) counts once."""
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    return sorted(unique.values(), key=lambda f: (-f.severity, f.tool, f.rule_id, f.location))


def evaluate(
    findings: list[Finding],
    baseline: list[BaselineEntry],
    threshold: Severity,
    today: dt.date,
    inputs: list[str],
) -> GateResult:
    findings = dedupe(findings)
    active = {e.fingerprint: e for e in baseline if not e.is_expired(today)}
    result = GateResult(threshold=threshold, inputs=inputs, findings=findings)
    result.expired = [e for e in baseline if e.is_expired(today)]
    used: set[str] = set()
    for finding in findings:
        entry = active.get(finding.fingerprint)
        if entry is not None:
            result.suppressed.append((finding, entry))
            used.add(entry.fingerprint)
        elif finding.severity >= threshold:
            result.blocking.append(finding)
        else:
            result.non_blocking.append(finding)
    result.stale = [e for e in active.values() if e.fingerprint not in used]
    return result


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(result: GateResult, max_rows: int = 50, report_only: bool = False) -> str:
    status = "✅ PASS" if result.passed else "❌ FAIL"
    if report_only:
        # The verdict is informational: say what the gate would decide without presenting it as a block.
        status = f"📋 REPORT ONLY (would {'pass' if result.passed else 'fail'})"
    totals = Counter(f.severity for f in result.findings)
    lines = [
        f"## Security quality gate: {status}",
        "",
        f"Fails on **new** findings with severity **{result.threshold.label}** or higher.",
        "",
        "| Severity | All findings | New, blocking |",
        "|---|---:|---:|",
    ]
    blocking = Counter(f.severity for f in result.blocking)
    for sev in reversed(Severity):
        lines.append(f"| {sev.label} | {totals.get(sev, 0)} | {blocking.get(sev, 0)} |")
    lines += [
        "",
        f"Suppressed by baseline: **{len(result.suppressed)}** · expired baseline entries: "
        f"**{len(result.expired)}** · stale baseline entries: **{len(result.stale)}**",
        "",
    ]
    if result.blocking:
        lines += [
            "### Blocking findings",
            "",
            "| Severity | Tool | Rule | Location | Title |",
            "|---|---|---|---|---|",
        ]
        for f in result.blocking[:max_rows]:
            lines.append(
                f"| {f.severity.label} | {f.tool} | `{_md_escape(f.rule_id)}` | "
                f"`{_md_escape(f.location)}` | {_md_escape(f.title)} |"
            )
        if len(result.blocking) > max_rows:
            lines.append(f"| … | | | | {len(result.blocking) - max_rows} more in gate-report.json |")
        lines.append("")
    if result.expired:
        lines += ["### Expired baseline entries (no longer suppressing)", ""]
        lines += [f"- `{e.fingerprint}` {e.tool} {e.rule_id} — expired {e.expires}" for e in result.expired]
        lines.append("")
    lines.append("Inputs: " + ", ".join(f"`{i}`" for i in result.inputs))
    return "\n".join(lines) + "\n"
