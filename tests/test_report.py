"""The report must be assembled from the documents the pipeline produces, so these tests check that it
parses them, and that it refuses to build a report when the findings table cannot be read.
"""

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

from tools import report

FINDINGS_MD = """# Security findings

Intro paragraph.

| ID | Title | OWASP API Top 10 (2023) | CWE | CVSS 3.1 | Test |
|---|---|---|---|---|---|
| [FINDING-001](#finding-001) | Unsigned token accepted | API2 Broken Authentication | CWE-347 | 9.1 critical | `test_a` |
| [FINDING-006](#finding-006) | Any user reads any vehicle | API1 BOLA | CWE-639 | 6.5 medium | `test_b` |
| [FINDING-011](#finding-011) | Feed exposes e-mail | API3 Property Level | CWE-213 | 4.3 medium | `test_c` |

## FINDING-001

Details.
"""


@pytest.fixture
def docs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "findings.md").write_text(FINDINGS_MD, encoding="utf-8")
    monkeypatch.setattr(report, "DOCS", tmp_path)
    monkeypatch.setattr(report, "REPORTS", tmp_path / "reports")
    return tmp_path


def test_findings_table_is_parsed(docs: Path) -> None:
    rows = report.findings_table()
    assert [r["id"] for r in rows] == ["FINDING-001", "FINDING-006", "FINDING-011"]
    assert rows[0] == {
        "id": "FINDING-001",
        "title": "Unsigned token accepted",
        "owasp": "API2 Broken Authentication",
        "cwe": "CWE-347",
        "score": "9.1",
        "severity": "critical",
    }


def test_missing_table_is_an_error(docs: Path) -> None:
    (docs / "findings.md").write_text("# Nothing here\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        report.findings_table()


def test_heat_map_counts_by_severity_and_category(docs: Path) -> None:
    html = report.heat_map(report.findings_table())
    for category in ("API1", "API2", "API3"):
        assert f"<th>{category}</th>" in html
    assert '<td class="sev-critical">1</td>' in html
    assert html.count('<td class="sev-medium">1</td>') == 2
    # A severity with no findings is rendered as an empty, uncoloured cell.
    assert '<td class="">' in html


def test_gate_summary_without_a_report(docs: Path) -> None:
    assert "make gate" in report.gate_summary()


def test_gate_summary_reads_the_gate_report(docs: Path) -> None:
    reports = docs / "reports"
    reports.mkdir()
    payload: dict[str, Any] = {
        "status": "pass",
        "generated_at": "2026-11-01T00:00:00+00:00",
        "counts": {"critical": 0, "high": 0},
    }
    (reports / "gate.json").write_text(json.dumps(payload), encoding="utf-8")
    summary = report.gate_summary()
    assert "PASS" in summary
    assert "critical 0" in summary


def test_section_drops_the_source_heading_and_renders_tables(docs: Path) -> None:
    html = report.section("4. Static analysis", docs / "findings.md")
    assert html.startswith("<h1>4. Static analysis</h1>")
    assert "<h1>Security findings</h1>" not in html
    assert "<table>" in html


def test_build_html_contains_cover_summary_and_findings(docs: Path) -> None:
    html = report.build_html(report.findings_table(), dt.date(2026, 11, 1))
    assert html.startswith("<!doctype html>")
    for expected in ("2026-11-01", "Executive summary", "Risk heat map", "FINDING-001", "9.1 critical"):
        assert expected in html, expected
    # Optional sections are included only when their document exists.
    assert "Dynamic analysis" not in html
    (docs / "scanner-coverage.md").write_text("# Coverage\n\nText.\n", encoding="utf-8")
    assert "Dynamic analysis" in report.build_html(report.findings_table(), dt.date(2026, 11, 1))


def test_main_writes_html_and_calls_the_printer(
    docs: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    printed: list[tuple[Path, Path]] = []

    def fake_to_pdf(html: Path, pdf: Path) -> None:
        printed.append((html, pdf))
        pdf.write_bytes(b"%PDF-1.4 fake")

    monkeypatch.setattr(report, "to_pdf", fake_to_pdf)
    out = docs / "out" / "assessment.pdf"
    monkeypatch.setattr("sys.argv", ["report", "--out", str(out), "--today", "2026-11-01"])
    assert report.main() == 0
    assert out.exists()
    assert printed
    assert printed[0][0].name == "security-assessment.html"
    assert "3 findings" in capsys.readouterr().out
