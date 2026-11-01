"""The expected scores are published vectors: CVEs scored by NVD and the examples in the CVSS v3.1
specification, so the implementation is checked against an external source rather than against itself.
"""

import pytest

from tools.cvss import CvssError, base_score, main, severity

PUBLISHED = [
    # CVE-2019-0708 (BlueKeep), NVD base score 9.8
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    # CVE-2021-44228 (Log4Shell), NVD 10.0, scope changed
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    # CVE-2014-0160 (Heartbleed), NVD 7.5
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    # CVE-2020-1472 (Zerologon), NVD 10.0
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    # CVE-2017-0144 (EternalBlue), NVD 8.1
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
    # CVE-2018-11776 (Struts), NVD 8.1
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
    # CVE-2019-11043 (PHP-FPM), NVD 9.8
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    # A classic authenticated BOLA read: NVD-style 6.5
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "medium"),
    # Stored data tampering by a privileged user, 4.9
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.9, "medium"),
    # No impact at all
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
    # Physical, high complexity, low impact. Not published: computed by hand from the specification —
    # exploitability 8.22 x 0.2 x 0.44 x 0.27 x 0.62 = 0.1211, impact 6.42 x 0.22 = 1.4124, sum 1.5335 -> 1.6.
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "low"),
]


@pytest.mark.parametrize(("vector", "expected", "rating"), PUBLISHED)
def test_published_vectors(vector: str, expected: float, rating: str) -> None:
    score = base_score(vector)
    assert score == expected
    assert severity(score) == rating


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no prefix
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X",  # unknown value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",  # unknown scope
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y",  # unknown metric
    ],
)
def test_invalid_vectors_are_rejected(vector: str) -> None:
    with pytest.raises(CvssError):
        base_score(vector)


def test_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"]) == 0
    assert "9.1" in capsys.readouterr().out
    assert main([]) == 2
