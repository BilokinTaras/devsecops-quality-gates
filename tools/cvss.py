"""CVSS v3.1 base score, implemented from the specification so every score in the findings is computed.

Specification: https://www.first.org/cvss/v3.1/specification-document (section 8.1, base metrics).

Usage: python -m tools.cvss CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
"""

from __future__ import annotations

import math
import sys

WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required depends on Scope.
PR_WEIGHTS: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    """The vector string is not a valid CVSS v3.1 base vector."""


def parse(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise CvssError("vector must start with CVSS:3.1")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        if key not in ORDER or not value:
            raise CvssError(f"unknown metric {part!r}")
        metrics[key] = value
    missing = [key for key in ORDER if key not in metrics]
    if missing:
        raise CvssError(f"missing base metrics: {', '.join(missing)}")
    return metrics


def _round_up(value: float) -> float:
    """Round up to one decimal, as Appendix A of the specification defines it."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse(vector)
    scope_changed = m["S"] == "C"
    try:
        iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
        exploitability = (
            8.22
            * WEIGHTS["AV"][m["AV"]]
            * WEIGHTS["AC"][m["AC"]]
            * PR_WEIGHTS[m["S"]][m["PR"]]
            * WEIGHTS["UI"][m["UI"]]
        )
    except KeyError as exc:
        raise CvssError(f"invalid metric value: {exc}") from None
    if m["S"] not in ("U", "C"):
        raise CvssError(f"invalid metric value: S:{m['S']}")

    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + exploitability), 10) if scope_changed else min(impact + exploitability, 10)
    return _round_up(raw)


def severity(score: float) -> str:
    """Qualitative rating from the specification's severity scale."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print(__doc__)
        return 2
    for vector in args:
        score = base_score(vector)
        print(f"{score:4.1f}  {severity(score):8}  {vector}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
