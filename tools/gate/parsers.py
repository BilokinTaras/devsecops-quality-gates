"""Parsers turning scanner reports into normalised findings.

Supported formats (``--input <format>:<path>``):

- ``sarif``         SARIF 2.1.0 from any tool (Semgrep, Trivy, Gitleaks, ZAP, Nuclei, CodeQL ...)
- ``trivy-json``    ``trivy ... --format json``
- ``gitleaks-json`` ``gitleaks ... --report-format json``
- ``semgrep-json``  ``semgrep --json``
- ``zap-json``      ZAP "traditional-json" report
- ``nuclei-jsonl``  ``nuclei -jsonl``
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from .models import Finding, Severity

Parser = Callable[[Any, str], Iterator[Finding]]

_CWE_RE = re.compile(r"cwe[-_/ :]*(\d+)", re.IGNORECASE)


def _cwes(values: Iterable[Any]) -> tuple[str, ...]:
    found: list[str] = []
    for value in values:
        for match in _CWE_RE.finditer(str(value)):
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in found:
                found.append(cwe)
    return tuple(found)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_line(text: Any, limit: int = 200) -> str:
    lines = str(text).strip().splitlines()
    return lines[0][:limit] if lines else ""


# ---------------------------------------------------------------- SARIF

_SARIF_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        score = props.get("security-severity")
        if score is not None:
            try:
                return Severity.from_cvss(float(score))
            except ValueError:
                pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return _SARIF_LEVEL.get(str(level), Severity.MEDIUM)


def _sarif_location(result: dict[str, Any]) -> str:
    for loc in result.get("locations") or []:
        physical = loc.get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if uri:
            line = (physical.get("region") or {}).get("startLine")
            return f"{uri}:{line}" if line else str(uri)
        for logical in loc.get("logicalLocations") or []:
            name = logical.get("fullyQualifiedName") or logical.get("name")
            if name:
                return str(name)
    web = result.get("webRequest") or {}
    if web.get("target"):
        return f"{web.get('method', 'GET')} {web['target']}"
    return "<no location>"


def parse_sarif(doc: Any, source: str) -> Iterator[Finding]:
    for run in doc.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = str(driver.get("name") or "sarif")
        rule_list: list[dict[str, Any]] = list(driver.get("rules") or [])
        rules = {str(r.get("id")): r for r in rule_list if r.get("id")}
        for result in run.get("results") or []:
            if result.get("suppressions"):
                continue
            declared_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
            rule = rules.get(str(declared_id)) if declared_id else None
            rule_index = result.get("ruleIndex")
            if rule is None and isinstance(rule_index, int) and 0 <= rule_index < len(rule_list):
                rule = rule_list[rule_index]
            rule = rule or {}
            rule_id = str(declared_id or rule.get("id") or "unknown")
            message = (result.get("message") or {}).get("text") or (rule.get("shortDescription") or {}).get(
                "text"
            )
            tags = _as_list((rule.get("properties") or {}).get("tags")) + _as_list(
                (result.get("properties") or {}).get("tags")
            )
            partial: dict[str, Any] = result.get("partialFingerprints") or {}
            hint = str(sorted(partial.items())[0][1]) if partial else ""
            yield Finding(
                tool=tool,
                rule_id=rule_id,
                severity=_sarif_severity(result, rule),
                title=_first_line(message or rule_id),
                location=_sarif_location(result),
                source=source,
                cwe=_cwes([*tags, rule.get("name", ""), rule_id]),
                fingerprint_hint=hint,
            )


# ---------------------------------------------------------------- Trivy JSON


def _trivy_severity(value: Any) -> Severity:
    try:
        return Severity.parse(str(value))
    except ValueError:
        return Severity.MEDIUM  # Trivy reports UNKNOWN when no score exists yet


def parse_trivy_json(doc: Any, source: str) -> Iterator[Finding]:
    artifact = str(doc.get("ArtifactName") or "")
    for result in doc.get("Results") or []:
        target = str(result.get("Target") or artifact)
        for vuln in result.get("Vulnerabilities") or []:
            pkg = f"{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}"
            yield Finding(
                tool="trivy",
                rule_id=str(vuln.get("VulnerabilityID")),
                severity=_trivy_severity(vuln.get("Severity")),
                title=_first_line(vuln.get("Title") or vuln.get("VulnerabilityID")),
                location=f"{target} {pkg}",
                source=source,
                cwe=_cwes(_as_list(vuln.get("CweIDs"))),
                fingerprint_hint=f"{artifact}|{target}|{pkg}",
            )
        for misconf in result.get("Misconfigurations") or []:
            line = (misconf.get("CauseMetadata") or {}).get("StartLine") or ""
            yield Finding(
                tool="trivy",
                rule_id=str(misconf.get("ID") or misconf.get("AVDID")),
                severity=_trivy_severity(misconf.get("Severity")),
                title=_first_line(misconf.get("Title") or misconf.get("ID")),
                location=f"{target}:{line}" if line else target,
                source=source,
            )
        for secret in result.get("Secrets") or []:
            yield Finding(
                tool="trivy",
                rule_id=str(secret.get("RuleID")),
                severity=_trivy_severity(secret.get("Severity")),
                title=_first_line(secret.get("Title") or secret.get("RuleID")),
                location=f"{target}:{secret.get('StartLine', '')}",
                source=source,
                cwe=("CWE-798",),
            )


# ---------------------------------------------------------------- Gitleaks JSON


def parse_gitleaks_json(doc: Any, source: str) -> Iterator[Finding]:
    for leak in _as_list(doc):
        location = f"{leak.get('File')}:{leak.get('StartLine')}"
        commit = str(leak.get("Commit") or "")[:12]
        yield Finding(
            tool="gitleaks",
            rule_id=str(leak.get("RuleID")),
            # A committed secret is always High: it must be rotated whatever the context.
            severity=Severity.HIGH,
            title=_first_line(leak.get("Description") or leak.get("RuleID")),
            location=f"{location}@{commit}" if commit else location,
            source=source,
            cwe=("CWE-798",),
            fingerprint_hint=str(leak.get("Fingerprint") or ""),
        )


# ---------------------------------------------------------------- Semgrep JSON

_SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def parse_semgrep_json(doc: Any, source: str) -> Iterator[Finding]:
    for res in doc.get("results") or []:
        extra = res.get("extra") or {}
        metadata = extra.get("metadata") or {}
        fingerprint = extra.get("fingerprint")
        yield Finding(
            tool="semgrep",
            rule_id=str(res.get("check_id")),
            severity=_SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
            title=_first_line(extra.get("message") or res.get("check_id")),
            location=f"{res.get('path')}:{(res.get('start') or {}).get('line', '')}",
            source=source,
            cwe=_cwes(_as_list(metadata.get("cwe"))),
            # Semgrep without login replaces the fingerprint with a placeholder.
            fingerprint_hint="" if fingerprint in (None, "requires login") else str(fingerprint),
        )


# ---------------------------------------------------------------- ZAP traditional JSON

_ZAP_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


def parse_zap_json(doc: Any, source: str) -> Iterator[Finding]:
    for site in _as_list(doc.get("site")):
        for alert in site.get("alerts") or []:
            severity = _ZAP_RISK.get(str(alert.get("riskcode")), Severity.MEDIUM)
            cwe = str(alert.get("cweid", ""))
            cwes = (f"CWE-{cwe}",) if cwe not in ("", "-1", "0") else ()
            seen: set[str] = set()
            for inst in alert.get("instances") or [{}]:
                where = f"{inst.get('method', '')} {inst.get('uri', site.get('@name', ''))}".strip()
                if inst.get("param"):
                    where += f" [{inst['param']}]"
                if where in seen:
                    continue
                seen.add(where)
                yield Finding(
                    tool="zap",
                    rule_id=str(alert.get("pluginid") or alert.get("alertRef")),
                    severity=severity,
                    title=_first_line(alert.get("alert") or alert.get("name")),
                    location=where,
                    source=source,
                    cwe=cwes,
                )


# ---------------------------------------------------------------- Nuclei JSONL


def parse_nuclei_jsonl(doc: Any, source: str) -> Iterator[Finding]:
    for item in _as_list(doc):
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        try:
            severity = Severity.parse(str(info.get("severity", "info")))
        except ValueError:
            severity = Severity.INFO
        yield Finding(
            tool="nuclei",
            rule_id=str(item.get("template-id")),
            severity=severity,
            title=_first_line(info.get("name") or item.get("template-id")),
            location=str(item.get("matched-at") or item.get("host") or ""),
            source=source,
            cwe=_cwes(_as_list(classification.get("cwe-id"))),
        )


PARSERS: dict[str, Parser] = {
    "sarif": parse_sarif,
    "trivy-json": parse_trivy_json,
    "gitleaks-json": parse_gitleaks_json,
    "semgrep-json": parse_semgrep_json,
    "zap-json": parse_zap_json,
    "nuclei-jsonl": parse_nuclei_jsonl,
}


def load_report(fmt: str, path: Path) -> list[Finding]:
    """Read one report. An empty file means the tool ran and found nothing."""
    if fmt not in PARSERS:
        raise ValueError(f"unknown input format {fmt!r}; expected one of {', '.join(sorted(PARSERS))}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    doc: Any
    if fmt == "nuclei-jsonl":
        doc = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        doc = json.loads(text)
    return list(PARSERS[fmt](doc, str(path)))
