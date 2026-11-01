"""Summarise image SCA results: Trivy vs Grype per crAPI image.

Usage: python -m tools.sca_summary reports/   -> prints Markdown and writes reports/sca-summary.md

Both tools scan the same image digest (Trivy directly, Grype from Syft's SBOM). Findings are compared
by (vulnerability ID, package); a GHSA ID is replaced by its CVE alias when the tool reports one, so the
same advisory under two names is not counted twice.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "other")


@dataclass
class ToolResult:
    by_severity: Counter[str] = field(default_factory=Counter)
    keys: set[tuple[str, str]] = field(default_factory=set)
    fixable_critical: int = 0


def _severity(value: Any) -> str:
    text = str(value or "").lower()
    return text if text in SEVERITIES[:-1] else "other"


def _alias(vuln_id: str, related: list[Any]) -> str:
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for item in related:
        rid = str(item.get("id", "")) if isinstance(item, dict) else str(item)
        if rid.startswith("CVE-"):
            return rid
    return vuln_id


def read_trivy(path: Path) -> ToolResult:
    result = ToolResult()
    doc = json.loads(path.read_text(encoding="utf-8"))
    seen: set[tuple[str, str]] = set()
    for res in doc.get("Results") or []:
        for vuln in res.get("Vulnerabilities") or []:
            key = (str(vuln.get("VulnerabilityID")), str(vuln.get("PkgName")))
            if key in seen:
                continue
            seen.add(key)
            severity = _severity(vuln.get("Severity"))
            result.by_severity[severity] += 1
            result.keys.add((_alias(key[0], vuln.get("VendorIDs") or []), key[1]))
            if severity == "critical" and vuln.get("FixedVersion"):
                result.fixable_critical += 1
    return result


def read_grype(path: Path) -> ToolResult:
    result = ToolResult()
    doc = json.loads(path.read_text(encoding="utf-8"))
    seen: set[tuple[str, str]] = set()
    for match in doc.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        key = (str(vuln.get("id")), str(artifact.get("name")))
        if key in seen:
            continue
        seen.add(key)
        severity = _severity(vuln.get("severity"))
        result.by_severity[severity] += 1
        result.keys.add((_alias(key[0], match.get("relatedVulnerabilities") or []), key[1]))
        if severity == "critical" and (vuln.get("fix") or {}).get("state") == "fixed":
            result.fixable_critical += 1
    return result


def summarise(reports: Path) -> str:
    lines = [
        "| Image | Tool | Critical | High | Medium | Low | Other | Critical with a fix |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    overlap = ["", "| Image | Found by both | Trivy only | Grype only |", "|---|---:|---:|---:|"]
    for trivy_path in sorted(reports.glob("trivy-image-*.json")):
        service = trivy_path.stem.removeprefix("trivy-image-")
        grype_path = reports / f"grype-{service}.json"
        tools = {"Trivy": read_trivy(trivy_path)}
        if grype_path.exists():
            tools["Grype"] = read_grype(grype_path)
        for name, res in tools.items():
            counts = " | ".join(str(res.by_severity[s]) for s in SEVERITIES)
            lines.append(f"| {service} | {name} | {counts} | {res.fixable_critical} |")
        if "Grype" in tools:
            t, g = tools["Trivy"].keys, tools["Grype"].keys
            overlap.append(f"| {service} | {len(t & g)} | {len(t - g)} | {len(g - t)} |")
    return "\n".join([*lines, *overlap]) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    reports = Path(args[0] if args else "reports")
    text = summarise(reports)
    (reports / "sca-summary.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
