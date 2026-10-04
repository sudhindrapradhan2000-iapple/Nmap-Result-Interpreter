"""Terminal table and Markdown report output."""

import textwrap
from datetime import datetime

from src.parser import Host
from src.validator import ALLOWED_SEVERITIES


LEGAL_WARNING = (
    "Use this tool only on scan results from systems you own or have "
    "explicit written permission to test. Unauthorized scanning is illegal."
)

HUMAN_REVIEW_NOTE = (
    "This report is advice only. A human must verify every finding before "
    "acting on it. Nothing here was exploited or changed automatically."
)


TABLE_COLUMNS = (
    ("Severity", 8),
    ("Host", 15),
    ("Port", 5),
    ("Service", 9),
    ("Risk", 32),
    ("Next step", 32),
)


def count_by_severity(
    findings: list[dict],
) -> dict[str, int]:
    """Return the number of findings for every severity."""

    counts = {
        severity: 0
        for severity in ALLOWED_SEVERITIES
    }

    for finding in findings:
        severity = finding["severity"]

        if severity in counts:
            counts[severity] += 1

    return counts


def summary_line(
    findings: list[dict],
) -> str:
    """Return a one-line severity summary."""

    counts = count_by_severity(
        findings
    )

    return ", ".join(
        f"{count} {severity}"
        for severity, count in counts.items()
    )


def _format_row(
    cells: list[str],
    widths: list[int],
) -> str:
    """Wrap table cells to fit the terminal table."""

    wrapped = [
        textwrap.wrap(
            str(cell),
            width,
        )
        or [""]
        for cell, width
        in zip(cells, widths)
    ]

    height = max(
        len(lines)
        for lines in wrapped
    )

    output_lines = []

    for index in range(height):

        parts = [
            (
                lines[index]
                if index < len(lines)
                else ""
            ).ljust(width)
            for lines, width
            in zip(wrapped, widths)
        ]

        output_lines.append(
            " | ".join(parts).rstrip()
        )

    return "\n".join(output_lines)


def format_terminal_table(
    findings: list[dict],
) -> str:
    """Return findings as a plain-text terminal table."""

    if not findings:
        return "No findings to display."

    widths = [
        width
        for _, width
        in TABLE_COLUMNS
    ]

    separator = "-+-".join(
        "-" * width
        for width in widths
    )

    lines = [
        _format_row(
            [
                name
                for name, _
                in TABLE_COLUMNS
            ],
            widths,
        ),
        separator,
    ]

    for finding in findings:

        row = [
            finding["severity"].upper(),
            finding.get("host", "-"),
            str(finding["port"]),
            finding["service"],
            finding["risk"],
            finding["next_step"],
        ]

        lines.append(
            _format_row(
                row,
                widths,
            )
        )

        lines.append(separator)

    return "\n".join(lines)


def _md_cell(
    text: str,
) -> str:
    """Make text safe inside a Markdown table."""

    return (
        str(text)
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def generate_markdown_report(
    scan_file: str,
    hosts: list[Host],
    findings: list[dict],
    hallucinated_cves: list[str],
    model: str,
    generated_at: datetime | None = None,
) -> str:
    """Build the complete Markdown report."""

    timestamp = (
        generated_at or datetime.now()
    ).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    lines: list[str] = [
        "# Nmap Result Interpreter Report",
        "",
        f"- **Scan file:** `{scan_file}`",
        f"- **Generated:** {timestamp}",
        f"- **Model:** `{model}`",
        "",
        f"> **Legal notice:** {LEGAL_WARNING}",
        "",
        f"> **Human review required:** {HUMAN_REVIEW_NOTE}",
        "",
        "## Executive summary",
        "",
        f"Total findings: **{len(findings)}**",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]

    for severity, count in (
        count_by_severity(
            findings
        ).items()
    ):
        lines.append(
            f"| {severity} | {count} |"
        )

    lines += [
        "",
        "## Hosts overview",
        "",
        "| IP | Hostname | State | Open ports | Total ports |",
        "|---|---|---|---|---|",
    ]

    for host in hosts:

        lines.append(
            f"| {_md_cell(host.ip)} "
            f"| {_md_cell(host.hostname) or '-'} "
            f"| {_md_cell(host.state)} "
            f"| {len(host.open_ports())} "
            f"| {len(host.ports)} |"
        )

    lines += [
        "",
        "## Findings",
    ]

    if not findings:
        lines += [
            "",
            "No findings were produced.",
        ]

    for severity in ALLOWED_SEVERITIES:

        group = [
            finding
            for finding in findings
            if finding["severity"]
            == severity
        ]

        if not group:
            continue

        lines += [
            "",
            f"### {severity.capitalize()} "
            f"({len(group)})",
        ]

        for finding in group:

            lines += [
                "",
                f"#### "
                f"{finding.get('host', '-')}:"
                f"{finding['port']} "
                f"({finding['service']})",
                "",
                f"- **Risk:** "
                f"{finding['risk']}",
                f"- **Evidence:** "
                f"{finding['evidence']}",
                f"- **Next step:** "
                f"{finding['next_step']}",
            ]

            if finding.get(
                "port_not_in_scan"
            ):
                lines.append(
                    "- **Warning:** this port was "
                    "not open in the scan; treat "
                    "this finding with suspicion."
                )

            if finding.get(
                "removed_cves"
            ):
                lines.append(
                    "- **Note:** removed CVE IDs "
                    "not found in the supplied data: "
                    + ", ".join(
                        finding["removed_cves"]
                    )
                )

    lines += [
        "",
        "## Limitations",
        "",
        "- CVE matches come from an NVD keyword "
        "search and are **unverified candidates**; "
        "they may relate to a different product "
        "or version.",
        "- The explanations were written by an "
        "LLM and can be wrong or incomplete. "
        "A human must review every finding.",
        f"- CVE IDs removed by the hallucination "
        f"guard: {len(hallucinated_cves)}.",
        "- Only open ports of hosts that were up "
        "were analyzed.",
        "- Scan data may be sent to the LLM provider; "
        "anonymize it if that is a concern.",
        "",
    ]

    return "\n".join(lines)
