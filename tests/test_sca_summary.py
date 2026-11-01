import json
from pathlib import Path

from tools.sca_summary import main, read_grype, read_trivy, summarise

TRIVY = {
    "Results": [
        {
            "Target": "image (debian 12)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "Severity": "CRITICAL",
                    "FixedVersion": "3.0.15",
                },
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "Severity": "CRITICAL",
                    "FixedVersion": "3.0.15",
                },
                {
                    "VulnerabilityID": "GHSA-aaaa-bbbb-cccc",
                    "PkgName": "jackson",
                    "Severity": "HIGH",
                    "VendorIDs": ["CVE-2024-0002"],
                },
                {"VulnerabilityID": "CVE-2024-0003", "PkgName": "zlib", "Severity": "UNKNOWN"},
            ],
        },
        {"Target": "app.jar", "Vulnerabilities": None},
    ]
}
GRYPE = {
    "matches": [
        {
            "vulnerability": {"id": "CVE-2024-0001", "severity": "Critical", "fix": {"state": "fixed"}},
            "artifact": {"name": "openssl"},
        },
        {
            "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "High", "fix": {"state": "not-fixed"}},
            "artifact": {"name": "jackson"},
            "relatedVulnerabilities": [{"id": "CVE-2024-0002"}],
        },
        {"vulnerability": {"id": "CVE-2024-0009", "severity": "Negligible"}, "artifact": {"name": "bash"}},
        {"vulnerability": {"id": "CVE-2024-0009", "severity": "Negligible"}, "artifact": {"name": "bash"}},
    ]
}


def _write(tmp_path: Path, name: str, doc: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_trivy_counts_unique_findings_and_fixable_criticals(tmp_path: Path) -> None:
    res = read_trivy(_write(tmp_path, "t.json", TRIVY))
    assert res.by_severity == {"critical": 1, "high": 1, "other": 1}
    assert res.fixable_critical == 1
    assert ("CVE-2024-0002", "jackson") in res.keys


def test_grype_counts_and_aliases(tmp_path: Path) -> None:
    res = read_grype(_write(tmp_path, "g.json", GRYPE))
    assert res.by_severity == {"critical": 1, "high": 1, "other": 1}
    assert res.fixable_critical == 1
    assert ("CVE-2024-0002", "jackson") in res.keys


def test_summary_compares_tools_per_image(tmp_path: Path) -> None:
    _write(tmp_path, "trivy-image-identity.json", TRIVY)
    _write(tmp_path, "grype-identity.json", GRYPE)
    _write(tmp_path, "trivy-image-web.json", {"Results": []})
    text = summarise(tmp_path)
    assert "| identity | Trivy | 1 | 1 | 0 | 0 | 1 | 1 |" in text
    assert "| identity | Grype | 1 | 1 | 0 | 0 | 1 | 1 |" in text
    assert "| identity | 2 | 1 | 1 |" in text
    assert "| web | Trivy | 0 | 0 | 0 | 0 | 0 | 0 |" in text
    assert "| web |" not in text.split("Found by both")[1]


def test_main_writes_markdown(tmp_path: Path) -> None:
    _write(tmp_path, "trivy-image-web.json", {"Results": []})
    assert main([str(tmp_path)]) == 0
    assert (tmp_path / "sca-summary.md").read_text(encoding="utf-8").startswith("| Image |")
