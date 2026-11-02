"""CLI: python -m tools.gate --input sarif:reports/semgrep.sarif --baseline security-baseline.yml"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import yaml

from .baseline import BaselineError, draft_entries, load_baseline
from .engine import evaluate, to_markdown
from .models import Finding, Severity
from .parsers import load_report

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def _parse_input(value: str) -> tuple[str, Path]:
    fmt, sep, path = value.partition(":")
    if not sep or not path:
        raise argparse.ArgumentTypeError(f"expected <format>:<path>, got {value!r}")
    return fmt, Path(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gate", description=__doc__)
    parser.add_argument(
        "--input", "-i", action="append", type=_parse_input, required=True, help="format:path"
    )
    parser.add_argument("--baseline", "-b", type=Path, help="YAML baseline of accepted findings")
    parser.add_argument("--fail-on", default="high", help="minimum severity that blocks (default: high)")
    parser.add_argument("--json-out", type=Path, help="write the full JSON report here")
    parser.add_argument("--md-out", type=Path, help="write a Markdown summary here")
    parser.add_argument("--write-baseline-draft", type=Path, help="write a triage draft of all findings")
    parser.add_argument("--owner", default="security-qa", help="owner for --write-baseline-draft")
    parser.add_argument("--today", type=dt.date.fromisoformat, help="override today's date (tests, audits)")
    parser.add_argument("--allow-missing", action="store_true", help="skip inputs whose file does not exist")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="evaluate and write reports but exit 0 (third-party targets the team cannot fix)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    today: dt.date = args.today or dt.datetime.now(dt.UTC).date()
    try:
        threshold = Severity.parse(args.fail_on)
        baseline = load_baseline(args.baseline)
    except (ValueError, BaselineError) as exc:
        print(f"gate: {exc}", file=sys.stderr)
        return EXIT_USAGE

    findings: list[Finding] = []
    inputs: list[str] = []
    for fmt, path in args.input:
        if not path.exists():
            if args.allow_missing:
                print(f"gate: skipping missing input {path}", file=sys.stderr)
                continue
            print(f"gate: input not found: {path}", file=sys.stderr)
            return EXIT_USAGE
        try:
            findings.extend(load_report(fmt, path))
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"gate: cannot parse {fmt}:{path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        inputs.append(f"{fmt}:{path.as_posix()}")

    if args.write_baseline_draft:
        draft = draft_entries(findings, owner=args.owner, today=today)
        args.write_baseline_draft.write_text(yaml.safe_dump(draft, sort_keys=False), encoding="utf-8")

    result = evaluate(findings, baseline, threshold, today, inputs)
    generated_at = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result.to_dict(generated_at), indent=2), encoding="utf-8")
    summary = to_markdown(result, report_only=args.report_only)
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(summary, encoding="utf-8")
    print(summary)
    if args.report_only:
        return EXIT_PASS
    return EXIT_PASS if result.passed else EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
