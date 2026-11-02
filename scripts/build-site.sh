#!/bin/sh
# Assembles the GitHub Pages site from the reports of a nightly run: gate verdicts, scanner summaries, the
# regression-test result, the ZAP HTML report, the PDF assessment and the SBOMs.
# Usage: scripts/build-site.sh [site-dir]   (reads reports/)
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
SITE=${1:-site}
mkdir -p "$SITE/zap" "$SITE/sbom"

cp "$REPORTS/security-assessment.pdf" "$SITE/" 2>/dev/null || true
cp "$REPORTS/zap/zap-report.html" "$SITE/zap/index.html" 2>/dev/null || true
for f in "$REPORTS"/sbom-*.cdx.json; do [ -f "$f" ] && cp "$f" "$SITE/sbom/"; done

esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
section() { # title, file
  printf '<h2>%s</h2>\n' "$1"
  if [ -f "$2" ]; then printf '<pre>'; esc < "$2"; printf '</pre>\n'; else printf '<p>not produced in this run</p>\n'; fi
}

tests_line=$(python3 - "$REPORTS/security-tests.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except (OSError, ET.ParseError):
    print("not produced in this run"); raise SystemExit
s = root if root.tag == "testsuite" else root.find("testsuite")
t, f, e, k = (int(s.get(x, 0)) for x in ("tests", "failures", "errors", "skipped"))
print(f"{t} tests: {t - f - e - k} positive controls passed, {k} strict expected failures (open findings), "
      f"{f} failed, {e} errors")
PY
)

sboms=$(find "$SITE/sbom" -name '*.json' | sort | sed "s|^$SITE/||; s|.*|<li><a href=\"&\">&</a></li>|")

{
  cat <<EOF
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>devsecops-quality-gates · nightly</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}
pre{background:#f4f4f4;padding:1rem;overflow:auto;font-size:13px}</style></head><body>
<h1>Security pipeline — nightly run $(date -u +%Y-%m-%d)</h1>
<p>OWASP crAPI on a throwaway local stand inside the CI runner. Nothing here was scanned outside that stand.</p>
<ul>
<li><a href="security-assessment.pdf">Security assessment (PDF)</a></li>
<li><a href="zap/index.html">ZAP report (HTML)</a></li>
</ul>
<h2>Regression tests</h2><p>$(printf '%s' "$tests_line" | esc)</p>
EOF
  section "Gate — this repository's code (blocking)" "$REPORTS/gate.md"
  section "Gate — DAST against the stand (blocking)" "$REPORTS/gate-target.md"
  section "crAPI images — Trivy vs Grype (report only)" "$REPORTS/sca-summary.md"
  section "crAPI images — gate view (report only)" "$REPORTS/gate-images.md"
  printf '<h2>SBOMs (CycloneDX)</h2><ul>%s</ul>\n</body></html>\n' "$sboms"
} > "$SITE/index.html"
echo "site: $SITE/index.html"
