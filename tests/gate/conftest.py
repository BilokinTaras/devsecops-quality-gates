from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

SARIF_SEMGREP: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep OSS",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.subprocess-shell-true",
                            "name": "subprocess-shell-true",
                            "shortDescription": {"text": "subprocess with shell=True"},
                            "properties": {
                                "security-severity": "7.5",
                                "tags": ["CWE-78: OS Command Injection"],
                            },
                        },
                        {
                            "id": "generic.style.note",
                            "defaultConfiguration": {"level": "note"},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.subprocess-shell-true",
                    "level": "error",
                    "message": {"text": "Found subprocess call with shell=True\nsecond line"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "tools/run.py"},
                                "region": {"startLine": 12},
                            }
                        }
                    ],
                },
                {"ruleIndex": 1, "message": {"text": "style"}, "locations": []},
                {
                    "ruleId": "python.lang.security.audit.subprocess-shell-true",
                    "message": {"text": "suppressed in source"},
                    "suppressions": [{"kind": "inSource"}],
                },
            ],
        }
    ],
}

SARIF_ZAP: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {"name": "ZAP", "rules": [{"id": "10038", "properties": {"tags": ["CWE-693"]}}]}
            },
            "results": [
                {
                    "ruleId": "10038",
                    "level": "warning",
                    "message": {"text": "Content Security Policy (CSP) Header Not Set"},
                    "locations": [{"logicalLocations": [{"fullyQualifiedName": "http://crapi-web/"}]}],
                    "partialFingerprints": {"b": "fp-b", "a": "fp-a"},
                },
                {
                    "ruleId": "40018",
                    "level": "bogus-level",
                    "message": {"text": "SQL Injection"},
                    "webRequest": {"method": "POST", "target": "http://crapi-web/community/api/v2/coupon"},
                    "properties": {"security-severity": "not-a-number"},
                },
                {"rule": {"id": "x"}, "message": {}, "locations": [{"logicalLocations": [{}]}]},
            ],
        }
    ],
}

TRIVY: dict[str, Any] = {
    "ArtifactName": "crapi/crapi-identity:v1.1.5",
    "Results": [
        {
            "Target": "app.jar",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2022-22965",
                    "PkgName": "org.springframework:spring-beans",
                    "InstalledVersion": "5.3.17",
                    "Severity": "CRITICAL",
                    "Title": "Spring4Shell",
                    "CweIDs": ["CWE-94"],
                },
                {
                    "VulnerabilityID": "CVE-2099-0001",
                    "PkgName": "lib",
                    "InstalledVersion": "1",
                    "Severity": "UNKNOWN",
                },
            ],
        },
        {
            "Target": "Dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Severity": "HIGH",
                    "Title": "Image user should not be root",
                    "CauseMetadata": {},
                },
                {
                    "ID": "DS026",
                    "Severity": "LOW",
                    "Title": "No HEALTHCHECK",
                    "CauseMetadata": {"StartLine": 3},
                },
            ],
            "Secrets": [
                {"RuleID": "private-key", "Severity": "CRITICAL", "Title": "Private key", "StartLine": 9}
            ],
        },
    ],
}

GITLEAKS: list[dict[str, Any]] = [
    {
        "RuleID": "qafake-demo-token",
        "Description": "Fake QA token used only to demonstrate the gate",
        "File": "demo/leak.txt",
        "StartLine": 1,
        "Commit": "0123456789abcdef",
        "Fingerprint": "0123456789abcdef:demo/leak.txt:qafake-demo-token:1",
    },
    {"RuleID": "generic-api-key", "File": "a.env", "StartLine": 2},
]

SEMGREP_JSON: dict[str, Any] = {
    "results": [
        {
            "check_id": "java.lang.security.audit.sqli.jdbc-sqli",
            "path": "services/workshop/Coupon.java",
            "start": {"line": 40},
            "extra": {
                "severity": "ERROR",
                "message": "Possible SQL injection",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                "fingerprint": "requires login",
            },
        },
        {
            "check_id": "go.lang.weird",
            "path": "x.go",
            "extra": {"severity": "SOMETHING", "fingerprint": "abc"},
        },
    ]
}

ZAP_JSON: dict[str, Any] = {
    "site": [
        {
            "@name": "http://crapi-web",
            "alerts": [
                {
                    "pluginid": "10021",
                    "alert": "X-Content-Type-Options Header Missing",
                    "riskcode": "1",
                    "cweid": "693",
                    "instances": [
                        {"uri": "http://crapi-web/a", "method": "GET"},
                        {"uri": "http://crapi-web/a", "method": "GET"},
                        {"uri": "http://crapi-web/b", "method": "POST", "param": "q"},
                    ],
                },
                {
                    "pluginid": "90022",
                    "alert": "Application Error Disclosure",
                    "riskcode": "2",
                    "cweid": "-1",
                },
            ],
        }
    ]
}

NUCLEI_JSONL = "\n".join(
    json.dumps(item)
    for item in [
        {
            "template-id": "mailhog-exposure",
            "info": {
                "name": "MailHog Exposure",
                "severity": "medium",
                "classification": {"cwe-id": ["cwe-200"]},
            },
            "matched-at": "http://mailhog:8025",
        },
        {"template-id": "weird", "info": {"severity": "nonsense"}, "host": "http://crapi-web"},
    ]
)


@pytest.fixture
def write(tmp_path: Path) -> Any:
    def _write(name: str, content: Any) -> Path:
        path = tmp_path / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    return _write
