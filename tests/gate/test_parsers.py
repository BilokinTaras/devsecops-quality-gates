from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.gate.conftest import (
    GITLEAKS,
    NUCLEI_JSONL,
    SARIF_SEMGREP,
    SARIF_ZAP,
    SEMGREP_JSON,
    TRIVY,
    ZAP_JSON,
)
from tools.gate.models import Finding, Severity
from tools.gate.parsers import load_report


def test_sarif_uses_security_severity_and_skips_suppressed(write: Any) -> None:
    findings = load_report("sarif", write("s.sarif", SARIF_SEMGREP))
    assert len(findings) == 2
    first, second = findings
    assert first.tool == "Semgrep OSS"
    assert first.severity is Severity.HIGH  # 7.5 from security-severity
    assert first.location == "tools/run.py:12"
    assert first.title == "Found subprocess call with shell=True"
    assert first.cwe == ("CWE-78",)
    assert second.rule_id == "generic.style.note"  # resolved through ruleIndex
    assert second.severity is Severity.LOW  # defaultConfiguration level "note"
    assert second.location == "<no location>"


def test_sarif_logical_location_web_request_and_fallbacks(write: Any) -> None:
    findings = load_report("sarif", write("z.sarif", SARIF_ZAP))
    csp, sqli, empty = findings
    assert csp.location == "http://crapi-web/"
    assert csp.severity is Severity.MEDIUM
    assert csp.fingerprint_hint == "fp-a"  # first partial fingerprint by key
    assert csp.cwe == ("CWE-693",)
    assert sqli.location == "POST http://crapi-web/community/api/v2/coupon"
    assert sqli.severity is Severity.MEDIUM  # unknown level and non-numeric score fall back
    assert empty.rule_id == "x"
    assert empty.location == "<no location>"


def test_trivy_vulnerabilities_misconfigurations_and_secrets(write: Any) -> None:
    findings = load_report("trivy-json", write("t.json", TRIVY))
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["CVE-2022-22965"].severity is Severity.CRITICAL
    assert by_rule["CVE-2022-22965"].location == "app.jar org.springframework:spring-beans@5.3.17"
    assert by_rule["CVE-2022-22965"].cwe == ("CWE-94",)
    assert by_rule["CVE-2099-0001"].severity is Severity.MEDIUM  # UNKNOWN
    assert by_rule["DS002"].location == "Dockerfile"
    assert by_rule["DS026"].location == "Dockerfile:3"
    assert by_rule["private-key"].cwe == ("CWE-798",)


def test_gitleaks_secrets_are_always_high(write: Any) -> None:
    demo, generic = load_report("gitleaks-json", write("g.json", GITLEAKS))
    assert demo.severity is Severity.HIGH
    assert demo.location == "demo/leak.txt:1@0123456789ab"
    assert demo.fingerprint_hint.endswith(":1")
    assert generic.location == "a.env:2"


def test_semgrep_json(write: Any) -> None:
    sqli, weird = load_report("semgrep-json", write("sg.json", SEMGREP_JSON))
    assert sqli.severity is Severity.HIGH
    assert sqli.cwe == ("CWE-89",)
    assert sqli.fingerprint_hint == ""  # "requires login" placeholder is ignored
    assert weird.severity is Severity.MEDIUM
    assert weird.fingerprint_hint == "abc"
    assert weird.location == "x.go:"


def test_zap_json_deduplicates_instances(write: Any) -> None:
    findings = load_report("zap-json", write("zap.json", ZAP_JSON))
    locations = [f.location for f in findings]
    assert locations == ["GET http://crapi-web/a", "POST http://crapi-web/b [q]", "http://crapi-web"]
    assert findings[0].severity is Severity.LOW
    assert findings[0].cwe == ("CWE-693",)
    assert findings[2].severity is Severity.MEDIUM
    assert findings[2].cwe == ()


def test_nuclei_jsonl(write: Any) -> None:
    mailhog, weird = load_report("nuclei-jsonl", write("n.jsonl", NUCLEI_JSONL))
    assert mailhog.severity is Severity.MEDIUM
    assert mailhog.cwe == ("CWE-200",)
    assert weird.severity is Severity.INFO
    assert weird.location == "http://crapi-web"


def test_empty_report_means_no_findings(write: Any) -> None:
    assert load_report("gitleaks-json", write("empty.json", "  \n")) == []


def test_unknown_format_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown input format"):
        load_report("csv", tmp_path / "x.csv")


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.8, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (7.0, Severity.HIGH),
        (4.0, Severity.MEDIUM),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_cvss_rating_scale(score: float, expected: Severity) -> None:
    assert Severity.from_cvss(score) is expected


def test_severity_parse_and_label() -> None:
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.CRITICAL.label == "critical"
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")


def test_fingerprint_is_stable_and_prefers_tool_hint() -> None:
    a = Finding("zap", "1", Severity.LOW, "t", "loc", "s")
    b = Finding("ZAP", "1", Severity.HIGH, "other title", "loc", "other source")
    c = Finding("zap", "1", Severity.LOW, "t", "loc-moved", "s", fingerprint_hint="same")
    d = Finding("zap", "1", Severity.LOW, "t", "loc", "s", fingerprint_hint="same")
    assert a.fingerprint == b.fingerprint  # title, severity and source do not change identity
    assert c.fingerprint == d.fingerprint  # tool fingerprint survives a moved location
    assert len(a.fingerprint) == 16
    assert a.to_dict()["severity"] == "low"
    assert "fingerprint_hint" not in a.to_dict()
