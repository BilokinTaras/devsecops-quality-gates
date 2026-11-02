from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.gate.conftest import GITLEAKS, TRIVY
from tools.gate.__main__ import EXIT_FAIL, EXIT_PASS, EXIT_USAGE, main
from tools.gate.baseline import BaselineEntry, BaselineError, draft_entries, load_baseline
from tools.gate.engine import dedupe, evaluate, to_markdown
from tools.gate.models import Finding, Severity

TODAY = dt.date(2026, 11, 1)


def finding(rule: str, sev: Severity, loc: str = "x", tool: str = "trivy") -> Finding:
    return Finding(tool, rule, sev, f"title {rule}", loc, "report.json")


def entry(f: Finding, expires: dt.date = dt.date(2027, 1, 1)) -> BaselineEntry:
    return BaselineEntry(f.fingerprint, f.tool, f.rule_id, f.location, "accepted: test", "qa", expires)


def write_baseline(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.write_text(yaml.safe_dump({"version": 1, "entries": entries}), encoding="utf-8")
    return path


class TestEvaluate:
    def test_new_high_blocks_and_lower_does_not(self) -> None:
        high, med = finding("H", Severity.HIGH), finding("M", Severity.MEDIUM)
        result = evaluate([high, med], [], Severity.HIGH, TODAY, [])
        assert not result.passed
        assert result.blocking == [high]
        assert result.non_blocking == [med]

    def test_baseline_suppresses_until_it_expires(self) -> None:
        crit = finding("C", Severity.CRITICAL)
        assert evaluate([crit], [entry(crit)], Severity.HIGH, TODAY, []).passed
        expired = evaluate([crit], [entry(crit, dt.date(2026, 10, 31))], Severity.HIGH, TODAY, [])
        assert not expired.passed
        assert len(expired.expired) == 1

    def test_expiry_day_itself_still_suppresses(self) -> None:
        crit = finding("C", Severity.CRITICAL)
        assert evaluate([crit], [entry(crit, TODAY)], Severity.HIGH, TODAY, []).passed

    def test_stale_entries_are_reported(self) -> None:
        gone = finding("GONE", Severity.HIGH)
        result = evaluate([], [entry(gone)], Severity.HIGH, TODAY, [])
        assert result.passed
        assert [e.rule_id for e in result.stale] == ["GONE"]

    def test_dedupe_keeps_one_per_fingerprint_sorted_by_severity(self) -> None:
        low, high = finding("A", Severity.LOW), finding("B", Severity.HIGH)
        assert dedupe([low, high, low]) == [high, low]

    def test_report_dict_and_markdown(self) -> None:
        high = finding("H|pipe", Severity.HIGH, loc="a\nb")
        sup = finding("S", Severity.CRITICAL)
        old = finding("OLD", Severity.HIGH)
        result = evaluate(
            [high, sup], [entry(sup), entry(old, dt.date(2020, 1, 1))], Severity.HIGH, TODAY, ["sarif:x"]
        )
        data = result.to_dict("2026-11-01T00:00:00+00:00")
        assert data["status"] == "fail"
        assert data["totals"]["by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}
        assert data["totals"]["suppressed"] == 1
        assert data["totals"]["expired_baseline"] == 1
        md = to_markdown(result)
        assert "❌ FAIL" in md
        assert "H\\|pipe" in md
        assert "a b" in md
        assert "Expired baseline entries" in md

    def test_markdown_report_only_is_not_a_verdict(self) -> None:
        result = evaluate([finding("H", Severity.HIGH)], [], Severity.HIGH, TODAY, [])
        md = to_markdown(result, report_only=True)
        assert "REPORT ONLY (would fail)" in md
        assert "❌ FAIL" not in md

    def test_markdown_truncates_long_lists(self) -> None:
        many = [finding(f"R{i}", Severity.HIGH, loc=str(i)) for i in range(5)]
        md = to_markdown(evaluate(many, [], Severity.HIGH, TODAY, []), max_rows=2)
        assert "3 more in gate-report.json" in md


class TestBaselineFile:
    def test_missing_file_is_empty_baseline(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "nope.yml") == []
        assert load_baseline(None) == []

    def test_valid_file(self, tmp_path: Path) -> None:
        f = finding("C", Severity.CRITICAL)
        path = write_baseline(tmp_path / "b.yml", [{**entry(f).to_dict(), "expires": "2027-01-01"}])
        [loaded] = load_baseline(path)
        assert loaded.fingerprint == f.fingerprint
        assert loaded.expires == dt.date(2027, 1, 1)

    @pytest.mark.parametrize(
        ("patch", "message"),
        [
            ({"reason": "TODO"}, "'reason' must be filled in"),
            ({"owner": ""}, "'owner' must be filled in"),
            ({"expires": "next year"}, "'expires' must be YYYY-MM-DD"),
        ],
    )
    def test_incomplete_entries_are_rejected(
        self, tmp_path: Path, patch: dict[str, str], message: str
    ) -> None:
        base = entry(finding("C", Severity.CRITICAL)).to_dict()
        path = write_baseline(tmp_path / "b.yml", [{**base, **patch}])
        with pytest.raises(BaselineError, match=message):
            load_baseline(path)

    def test_structure_errors(self, tmp_path: Path) -> None:
        bad_version = tmp_path / "v.yml"
        bad_version.write_text("version: 2\n", encoding="utf-8")
        with pytest.raises(BaselineError, match="version: 1"):
            load_baseline(bad_version)
        not_mapping = write_baseline(tmp_path / "m.yml", ["just a string"])  # type: ignore[list-item]
        with pytest.raises(BaselineError, match="must be a mapping"):
            load_baseline(not_mapping)
        e = entry(finding("C", Severity.CRITICAL)).to_dict()
        dup = write_baseline(tmp_path / "d.yml", [e, e])
        with pytest.raises(BaselineError, match="duplicate fingerprint"):
            load_baseline(dup)

    def test_draft_requires_human_reason(self) -> None:
        f = finding("C", Severity.CRITICAL)
        draft = draft_entries([f, f], owner="qa", today=TODAY)
        assert len(draft["entries"]) == 1
        assert draft["entries"][0]["reason"] == "TODO"
        assert draft["entries"][0]["expires"] == "2027-01-30"


class TestCli:
    def test_fails_on_new_critical_and_writes_reports(self, tmp_path: Path, write: Any) -> None:
        trivy = write("trivy.json", TRIVY)
        out_json, out_md = tmp_path / "out/gate.json", tmp_path / "out/gate.md"
        code = main(
            [
                "-i",
                f"trivy-json:{trivy}",
                "--json-out",
                str(out_json),
                "--md-out",
                str(out_md),
                "--today",
                "2026-11-01",
            ]
        )
        assert code == EXIT_FAIL
        assert json.loads(out_json.read_text(encoding="utf-8"))["status"] == "fail"
        assert "FAIL" in out_md.read_text(encoding="utf-8")

    def test_passes_when_all_blocking_findings_are_baselined(self, tmp_path: Path, write: Any) -> None:
        leaks = write("gitleaks.json", GITLEAKS)
        draft = tmp_path / "draft.yml"
        assert main(["-i", f"gitleaks-json:{leaks}", "--write-baseline-draft", str(draft)]) == EXIT_FAIL
        doc = yaml.safe_load(draft.read_text(encoding="utf-8"))
        for e in doc["entries"]:
            e["reason"] = "demo fixture, not a real secret"
        baseline = write_baseline(tmp_path / "baseline.yml", doc["entries"])
        assert main(["-i", f"gitleaks-json:{leaks}", "-b", str(baseline)]) == EXIT_PASS

    def test_threshold_critical_lets_high_through(self, write: Any) -> None:
        leaks = write("gitleaks.json", GITLEAKS)
        assert main(["-i", f"gitleaks-json:{leaks}", "--fail-on", "critical"]) == EXIT_PASS

    def test_report_only_reports_failure_but_exits_zero(self, tmp_path: Path, write: Any) -> None:
        trivy = write("trivy.json", TRIVY)
        out_json = tmp_path / "gate.json"
        assert main(["-i", f"trivy-json:{trivy}", "--report-only", "--json-out", str(out_json)]) == EXIT_PASS
        assert json.loads(out_json.read_text(encoding="utf-8"))["status"] == "fail"

    def test_usage_errors(self, tmp_path: Path, write: Any) -> None:
        assert main(["-i", f"sarif:{tmp_path / 'missing.sarif'}"]) == EXIT_USAGE
        assert main(["-i", f"sarif:{tmp_path / 'missing.sarif'}", "--allow-missing"]) == EXIT_PASS
        assert main(["-i", f"sarif:{write('bad.sarif', '{not json')}"]) == EXIT_USAGE
        assert main(["-i", f"csv:{write('x.csv', 'a,b')}"]) == EXIT_USAGE
        assert main(["-i", f"sarif:{write('ok.sarif', '{}')}", "--fail-on", "urgent"]) == EXIT_USAGE
        bad_baseline = write("b.yml", "version: 3\n")
        assert main(["-i", f"sarif:{write('ok2.sarif', '{}')}", "-b", str(bad_baseline)]) == EXIT_USAGE
        with pytest.raises(SystemExit):
            main(["-i", "no-colon"])
