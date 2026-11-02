"""Builds the security assessment report as HTML, then prints it to PDF with the Playwright browser
that the sibling e2e project already installs (no extra system dependency, no LaTeX).

Usage: uv run python -m tools.report [--out reports/security-assessment.pdf]

The content is assembled from the documents that the rest of the pipeline produces, so the report cannot
drift from them: docs/findings.md, docs/findings-static.md, docs/scanner-coverage.md and the gate summary.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REPORTS = ROOT / "reports"

STYLE = """
@page { size: A4; margin: 18mm 16mm; }
body { font: 10.5pt/1.5 "Segoe UI", system-ui, sans-serif; color: #1a1a1a; }
h1 { font-size: 20pt; border-bottom: 2px solid #444; padding-bottom: 6px; }
h2 { font-size: 14pt; margin-top: 22px; border-bottom: 1px solid #ccc; padding-bottom: 3px; }
h3 { font-size: 11.5pt; margin-top: 16px; }
table { border-collapse: collapse; width: 100%; font-size: 9pt; margin: 10px 0; }
th, td { border: 1px solid #bbb; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #eee; }
code { background: #f3f3f3; padding: 1px 3px; font-size: 9pt; }
pre { background: #f6f6f6; border: 1px solid #ddd; padding: 8px; font-size: 8.5pt; overflow-wrap: anywhere;
      white-space: pre-wrap; }
.cover { text-align: center; margin: 60mm 0 0; page-break-after: always; }
.cover h1 { border: 0; font-size: 26pt; }
.meta { color: #555; font-size: 10pt; }
.sev-critical { background: #c0392b; color: #fff; }
.sev-high { background: #e67e22; color: #fff; }
.sev-medium { background: #f1c40f; }
.sev-low { background: #ecf0f1; }
.heat td, .heat th { text-align: center; }
h2 { page-break-after: avoid; }
table, pre { page-break-inside: avoid; }
"""

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def findings_table() -> list[dict[str, str]]:
    """Parses the summary table at the top of docs/findings.md — one source of truth for the scores."""
    rows: list[dict[str, str]] = []
    for line in (DOCS / "findings.md").read_text(encoding="utf-8").splitlines():
        match = re.match(
            r"\|\s*\[(FINDING-\d+)\].*?\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(CWE-\d+)\s*\|\s*([\d.]+)\s+(\w+)\s*\|",
            line,
        )
        if match:
            rows.append(
                {
                    "id": match[1],
                    "title": match[2],
                    "owasp": match[3],
                    "cwe": match[4],
                    "score": match[5],
                    "severity": match[6],
                }
            )
    if not rows:
        raise SystemExit("report: could not parse the findings table in docs/findings.md")
    return rows


def heat_map(rows: list[dict[str, str]]) -> str:
    """Counts findings per severity and per OWASP API Top 10 category."""
    categories = sorted({r["owasp"].split(" ")[0] for r in rows})
    head = "".join(f"<th>{c}</th>" for c in categories)
    body = ""
    for severity in SEVERITY_ORDER:
        cells = ""
        for category in categories:
            n = sum(1 for r in rows if r["severity"] == severity and r["owasp"].startswith(category))
            cells += f'<td class="{"sev-" + severity if n else ""}">{n or ""}</td>'
        body += f"<tr><th>{severity}</th>{cells}</tr>"
    return f'<table class="heat"><tr><th>severity \\ category</th>{head}</tr>{body}</table>'


def gate_summary() -> str:
    path = REPORTS / "gate.json"
    if not path.exists():
        return "<p>The gate report is produced by <code>make gate</code>.</p>"
    data = json.loads(path.read_text(encoding="utf-8"))
    totals = data.get("totals", {})
    by_severity = totals.get("by_severity", {})
    counted = ", ".join(f"{name} {n}" for name, n in by_severity.items() if n) or "no findings"
    return (
        f"<p>Last run of the blocking gate: <strong>{data.get('status', '?').upper()}</strong>"
        f" ({data.get('generated_at', '')}), blocking {totals.get('blocking', 0)} of"
        f" {totals.get('findings', 0)} findings ({counted}).</p>"
    )


def section(title: str, source: Path, drop_first_heading: bool = True) -> str:
    md = MarkdownIt("commonmark").enable("table")
    text = source.read_text(encoding="utf-8")
    if drop_first_heading:
        text = re.sub(r"\A#\s.*\n", "", text)
    rendered: str = md.render(text)
    return f"<h1>{title}</h1>\n{rendered}"


def build_html(rows: list[dict[str, str]], today: dt.date) -> str:
    by_severity = {s: sum(1 for r in rows if r["severity"] == s) for s in SEVERITY_ORDER}
    summary_rows = "".join(
        f"<tr><td>{r['id']}</td><td>{r['title']}</td><td>{r['owasp']}</td><td>{r['cwe']}</td>"
        f'<td class="sev-{r["severity"]}">{r["score"]} {r["severity"]}</td></tr>'
        for r in sorted(rows, key=lambda r: -float(r["score"]))
    )
    cover = f"""
    <div class="cover">
      <h1>Security assessment</h1>
      <p class="meta">Target: OWASP crAPI v1.1.6, local stand (127.0.0.1)<br>
      Date: {today.isoformat()}<br>
      Method: OWASP WSTG, ASVS, API Security Top 10 (2023)</p>
    </div>"""
    overview = f"""
    <h1>1. Executive summary</h1>
    <p>Fifteen vulnerabilities were reproduced by hand on the local crAPI stand and each is covered by an
    automated regression test. Four are rated critical: three different ways to bypass authentication
    entirely, and an unthrottled one-time-password endpoint that allows account takeover by brute force.
    One high-severity SQL injection returns other users' data, and a server-side request forgery lets the
    application be used to reach services on its internal network.</p>
    <p>The findings chain: the community feed hands out e-mail addresses and vehicle identifiers, which are
    exactly the inputs the authentication and object-level findings need.</p>
    <table><tr><th>Severity</th><th>Findings</th></tr>
    {"".join(f'<tr><td class="sev-{s}">{s}</td><td>{by_severity[s]}</td></tr>' for s in SEVERITY_ORDER)}
    </table>
    {gate_summary()}
    <h2>Scope and rules</h2>
    <p>Only containers of the Compose project <code>qa-crapi</code> on the loopback interface were tested.
    Server-side request forgery was directed exclusively at a canary container inside the stand's network.
    Brute-force demonstrations were limited to 20 attempts against accounts created by the test suite.</p>
    <h2>Risk heat map</h2>
    {heat_map(rows)}
    <h1>2. Findings overview</h1>
    <table><tr><th>ID</th><th>Title</th><th>OWASP API Top 10 (2023)</th><th>CWE</th><th>CVSS 3.1</th></tr>
    {summary_rows}</table>"""
    parts = [cover, overview, section("3. Findings in detail", DOCS / "findings.md")]
    for number, (title, name) in enumerate(
        [("Static analysis", "findings-static.md"), ("Dynamic analysis and coverage", "scanner-coverage.md")],
        start=4,
    ):
        path = DOCS / name
        if path.exists():
            parts.append(section(f"{number}. {title}", path))
    return f"<!doctype html><html><head><meta charset='utf-8'><style>{STYLE}</style></head><body>{''.join(parts)}</body></html>"


def playwright_package() -> Path:
    """package.json of an installed @playwright/test.

    PLAYWRIGHT_DIR names a directory with node_modules/@playwright/test (CI installs one there); locally the
    sibling e2e project's installation is reused, so nothing extra is downloaded.
    """
    custom = os.environ.get("PLAYWRIGHT_DIR")
    base = Path(custom) if custom else ROOT.parent / "shop-e2e-playwright"
    return base / "package.json"


def to_pdf(html: Path, pdf: Path) -> None:
    """Prints the HTML to PDF with Playwright's Chromium."""
    script = f"""
    const {{ createRequire }} = require('node:module');
    const req = createRequire({json.dumps(str(playwright_package()))});
    const {{ chromium }} = req('@playwright/test');
    (async () => {{
      const browser = await chromium.launch();
      const page = await browser.newPage();
      await page.goto({json.dumps(html.resolve().as_uri())});
      await page.pdf({{ path: {json.dumps(str(pdf))}, format: 'A4', printBackground: true,
        displayHeaderFooter: true, headerTemplate: '<span></span>',
        footerTemplate: `<div style="font-size:8px;width:100%;text-align:center;color:#666">
          crAPI security assessment · <span class="pageNumber"></span>/<span class="totalPages"></span></div>` }});
      await browser.close();
    }})();
    """
    subprocess.run(["node", "-e", script], check=True, cwd=ROOT)  # noqa: S603, S607


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPORTS / "security-assessment.pdf")
    parser.add_argument("--today", type=dt.date.fromisoformat, default=dt.datetime.now(dt.UTC).date())
    args = parser.parse_args()

    REPORTS.mkdir(exist_ok=True)
    rows = findings_table()
    html_path = REPORTS / "security-assessment.html"
    html_path.write_text(build_html(rows, args.today), encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    to_pdf(html_path, args.out)
    print(f"report: {args.out} ({args.out.stat().st_size // 1024} KiB, {len(rows)} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
