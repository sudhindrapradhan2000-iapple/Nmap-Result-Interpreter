"""Evaluate Nmap Result Interpreter findings against hand-written ground truth.

This module is offline and does not call OpenAI or NVD.

Usage:
    python -m src.evaluate --findings output\\findings.json
    python -m src.evaluate --findings output\\findings.json --truth samples\\ground_truth.json
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from src.validator import CVE_PATTERN, SEVERITY_RANK


@dataclass
class EvalRow:
    """Result for one expected finding."""

    expected: str
    found: bool
    agent_severity: str
    min_severity: str
    severity_ok: bool
    cve_hits: str

    @property
    def passed(self) -> bool:
        """A finding passes when it was found and meets the severity requirement."""
        return self.found and self.severity_ok


def load_json(path: str) -> dict:
    """Load a JSON object from a file."""

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise ValueError(f"Cannot read JSON file '{path}': {err}") from err

    if not isinstance(data, dict):
        raise ValueError(f"'{path}' must contain a JSON object.")

    return data


def services_match(expected: str, found: str) -> bool:
    """Compare service names case-insensitively."""

    expected_name = expected.strip().lower()
    found_name = found.strip().lower()

    if not expected_name or not found_name:
        return False

    return (
        expected_name == found_name
        or expected_name in found_name
        or found_name in expected_name
    )


def find_match(
    findings: list[dict],
    expected: dict,
    used_indices: set[int],
) -> tuple[int, dict] | None:
    """Find one unused agent finding matching host, port and service."""

    for index, finding in enumerate(findings):
        if index in used_indices:
            continue

        if (
            finding.get("host") == expected.get("host")
            and finding.get("port") == expected.get("port")
            and services_match(
                str(expected.get("service", "")),
                str(finding.get("service", "")),
            )
        ):
            return index, finding

    return None


def evaluate(
    findings_doc: dict,
    truth_doc: dict,
) -> tuple[list[EvalRow], dict]:
    """Evaluate findings against the ground truth."""

    expected_list = truth_doc.get("expected_findings")

    if not isinstance(expected_list, list):
        raise ValueError(
            'Ground truth needs an "expected_findings" list.'
        )

    findings = findings_doc.get("findings", [])

    if not isinstance(findings, list):
        raise ValueError(
            'Findings JSON needs a "findings" list.'
        )

    rows: list[EvalRow] = []

    # Keep track of findings already matched to an expected finding.
    # This prevents one agent finding from satisfying multiple ground-truth rows.
    used_indices: set[int] = set()

    for expected in expected_list:
        if not isinstance(expected, dict):
            raise ValueError(
                "Every item in expected_findings must be a JSON object."
            )

        min_severity = str(
            expected.get("min_severity", "")
        ).lower()

        if min_severity not in SEVERITY_RANK:
            raise ValueError(
                f"Invalid min_severity '{min_severity}' in ground truth."
            )

        match = find_match(
            findings,
            expected,
            used_indices,
        )

        label = (
            f"{expected.get('host', '?')}:"
            f"{expected.get('port', '?')} "
            f"{expected.get('service', '?')}"
        )

        if match is None:
            rows.append(
                EvalRow(
                    expected=label,
                    found=False,
                    agent_severity="-",
                    min_severity=min_severity,
                    severity_ok=False,
                    cve_hits="n/a",
                )
            )
            continue

        index, finding = match
        used_indices.add(index)

        agent_severity = str(
            finding.get("severity", "")
        ).lower()

        if agent_severity not in SEVERITY_RANK:
            raise ValueError(
                f"Invalid agent severity '{agent_severity}' "
                f"for {label}."
            )

        # Lower SEVERITY_RANK means more severe.
        # Therefore medium satisfies a low minimum, but low does not satisfy medium.
        severity_ok = (
            SEVERITY_RANK[agent_severity]
            <= SEVERITY_RANK[min_severity]
        )

        valid_cves = [
            cve
            for cve in expected.get("expected_cves", [])
            if isinstance(cve, str)
            and CVE_PATTERN.fullmatch(cve)
        ]

        searchable_text = " ".join(
            str(finding.get(key, ""))
            for key in ("risk", "evidence", "next_step")
        ).upper()

        hits = sum(
            1
            for cve in valid_cves
            if cve.upper() in searchable_text
        )

        cve_text = (
            f"{hits}/{len(valid_cves)}"
            if valid_cves
            else "n/a"
        )

        rows.append(
            EvalRow(
                expected=label,
                found=True,
                agent_severity=agent_severity,
                min_severity=min_severity,
                severity_ok=severity_ok,
                cve_hits=cve_text,
            )
        )

    # -----------------------------
    # Precision / recall / F1
    # -----------------------------

    total_expected = len(expected_list)
    total_predictions = len(findings)

    true_positives = sum(
        1 for row in rows if row.found
    )

    recall = (
        true_positives / total_expected
        if total_expected
        else 0.0
    )

    precision = (
        true_positives / total_predictions
        if total_predictions
        else 0.0
    )

    if precision + recall:
        f1 = (
            2 * precision * recall
            / (precision + recall)
        )
    else:
        f1 = 0.0

    severity_matches = sum(
        1
        for row in rows
        if row.found and row.severity_ok
    )

    severity_accuracy = (
        severity_matches / true_positives
        if true_positives
        else 0.0
    )

    # -----------------------------
    # Hallucination detection
    # -----------------------------

    open_ports = {
        host.get("ip"): set(host.get("open_ports", []))
        for host in findings_doc.get("hosts", [])
        if isinstance(host, dict)
    }

    unknown_port_findings = 0

    for finding in findings:
        host = finding.get("host")
        port = finding.get("port")

        if port not in open_ports.get(host, set()):
            unknown_port_findings += 1

    removed_cves = findings_doc.get(
        "hallucinated_cves",
        [],
    )

    if not isinstance(removed_cves, list):
        removed_cves = []

    hallucinations = (
        len(removed_cves)
        + unknown_port_findings
    )

    summary = {
        "total_expected": total_expected,
        "total_predictions": total_predictions,
        "true_positives": true_positives,
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "severity_matches": severity_matches,
        "severity_accuracy": severity_accuracy,
        "hallucinations": hallucinations,
        "removed_cves": len(removed_cves),
        "unknown_port_findings": unknown_port_findings,
    }

    return rows, summary


def format_results(rows: list[EvalRow]) -> str:
    """Format evaluation rows as a readable table."""

    headers = [
        "Expected",
        "Found",
        "Agent sev.",
        "Min sev.",
        "CVE hits",
        "Result",
    ]

    table = [
        [
            row.expected,
            "YES" if row.found else "NO",
            row.agent_severity,
            row.min_severity,
            row.cve_hits,
            "PASS" if row.passed else "FAIL",
        ]
        for row in rows
    ]

    if not table:
        return "No expected findings."

    widths = [
        max(
            len(str(value))
            for value in column
        )
        for column in zip(headers, *table)
    ]

    separator = "-+-".join(
        "-" * width
        for width in widths
    )

    output = [
        " | ".join(
            header.ljust(width)
            for header, width in zip(headers, widths)
        ),
        separator,
    ]

    for row in table:
        output.append(
            " | ".join(
                str(value).ljust(width)
                for value, width in zip(row, widths)
            )
        )

    return "\n".join(output)


def main() -> None:
    """Command-line entry point."""

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate Nmap Result Interpreter findings "
            "against a ground-truth JSON file."
        )
    )

    parser.add_argument(
        "--findings",
        required=True,
        help=(
            "JSON file produced by "
            "python -m src.main --json-out"
        ),
    )

    parser.add_argument(
        "--truth",
        default="samples/ground_truth.json",
        help=(
            "Ground-truth JSON file "
            "(default: samples/ground_truth.json)"
        ),
    )

    args = parser.parse_args()

    try:
        findings_doc = load_json(args.findings)
        truth_doc = load_json(args.truth)

        rows, summary = evaluate(
            findings_doc,
            truth_doc,
        )

    except (ValueError, KeyError) as err:
        print(
            f"Error: {err}",
            file=sys.stderr,
        )
        sys.exit(1)

    print()
    print("=== Nmap Result Interpreter Evaluation ===")
    print()

    print(format_results(rows))

    print()
    print(
        f"Recall:             "
        f"{summary['true_positives']}/"
        f"{summary['total_expected']} "
        f"= {summary['recall']:.1%}"
    )

    print(
        f"Precision:          "
        f"{summary['true_positives']}/"
        f"{summary['total_predictions']} "
        f"= {summary['precision']:.1%}"
    )

    print(
        f"F1 score:           "
        f"{summary['f1']:.1%}"
    )

    print(
        f"Severity match:     "
        f"{summary['severity_matches']}/"
        f"{summary['true_positives']} "
        f"= {summary['severity_accuracy']:.1%}"
    )

    print(
        f"Hallucinations:     "
        f"{summary['hallucinations']}"
    )

    print(
        f"  Removed CVEs:     "
        f"{summary['removed_cves']}"
    )

    print(
        f"  Unknown ports:    "
        f"{summary['unknown_port_findings']}"
    )


if __name__ == "__main__":
    main()
