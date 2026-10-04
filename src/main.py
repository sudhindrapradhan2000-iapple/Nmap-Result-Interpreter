"""Command-line entry point for the Nmap Result Interpreter.

Run from the project root:

    python -m src.main samples\\scan.xml
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from src.analyzer import (
    MissingApiKeyError,
    analyze_hosts,
    create_client,
)

from src.config import OPENAI_MODEL

from src.cve_lookup import CveLookup
from src.parser import (
    Host,
    ScanParseError,
    parse_nmap_xml,
)
from src.report import (
    LEGAL_WARNING,
    format_terminal_table,
    generate_markdown_report,
    summary_line,
)


EXIT_OK = 0
EXIT_INPUT_ERROR = 1
EXIT_MISSING_KEY = 2


logger = logging.getLogger(
    "nmap_interpreter"
)


def build_arg_parser() -> argparse.ArgumentParser:
    """Define command-line options."""

    parser = argparse.ArgumentParser(
        description=(
            "Defensive, read-only interpreter "
            "for Nmap XML scan results."
        )
    )

    parser.add_argument(
        "scan_file",
        nargs="?",
        help="Path to an Nmap XML file.",
    )

    parser.add_argument(
        "--input",
        "-i",
        dest="input_opt",
        help="Same as the positional scan file.",
    )

    parser.add_argument(
        "--format",
        choices=("table", "markdown"),
        default="table",
        help="Output format.",
    )

    parser.add_argument(
        "--model",
        default=OPENAI_MODEL,
        help=(
            f"OpenAI model to use "
            f"(default: {OPENAI_MODEL})."
        ),
    )

    parser.add_argument(
        "--output",
        help="Write the report to this file.",
    )

    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip NVD lookups.",
    )

    parser.add_argument(
        "--json-out",
        help=(
            "Save validated findings as JSON "
            "for evaluation."
        ),
    )

    return parser


def write_text(
    path_str: str,
    text: str,
) -> None:
    """Write UTF-8 text to a file."""

    path = Path(path_str)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        text,
        encoding="utf-8",
    )


def build_json_output(
    scan_file: str,
    hosts: list[Host],
    findings: list[dict],
    hallucinated: list[str],
) -> dict:
    """Build JSON output for evaluate.py."""

    return {
        "scan_file": scan_file,
        "hosts": [
            {
                "ip": host.ip,
                "open_ports": [
                    port.number
                    for port in host.open_ports()
                ],
            }
            for host in hosts
        ],
        "findings": findings,
        "hallucinated_cves": hallucinated,
    }


def run(
    argv: list[str] | None = None,
) -> int:
    """Run the complete pipeline."""

    if hasattr(
        sys.stdout,
        "reconfigure",
    ):
        sys.stdout.reconfigure(
            encoding="utf-8",
            errors="replace",
        )

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    arg_parser = build_arg_parser()

    args = arg_parser.parse_args(argv)

    scan_path = (
        args.input_opt
        or args.scan_file
    )

    if not scan_path:
        arg_parser.error(
            "Please provide the Nmap XML file."
        )

    print(
        "=== Nmap Result Interpreter "
        "(defensive, read-only) ==="
    )

    print(
        f"LEGAL: {LEGAL_WARNING}\n"
    )

    # -------------------------------------------------
    # 1. Parse the Nmap XML file
    # -------------------------------------------------

    try:

        hosts = parse_nmap_xml(
            scan_path
        )

    except FileNotFoundError as err:

        print(
            f"Error: {err}",
            file=sys.stderr,
        )

        return EXIT_INPUT_ERROR

    except ScanParseError as err:

        print(
            f"Error: could not read "
            f"the scan: {err}",
            file=sys.stderr,
        )

        return EXIT_INPUT_ERROR

    # -------------------------------------------------
    # 2. Create the OpenAI client
    # -------------------------------------------------

    try:

        client = create_client()

    except MissingApiKeyError as err:

        print(
            f"Error: {err}",
            file=sys.stderr,
        )

        return EXIT_MISSING_KEY

    # -------------------------------------------------
    # 3. Select hosts that are up and have open ports
    # -------------------------------------------------

    targets = [
        host
        for host in hosts
        if (
            host.state == "up"
            and host.open_ports()
        )
    ]

    if not targets:

        print(
            "No hosts that are up with "
            "open ports were found."
        )

        print(
            "Nothing to analyze."
        )

        return EXIT_OK

    # -------------------------------------------------
    # 4. NVD CVE lookup
    # -------------------------------------------------

    if args.no_cve:

        lookup = None

    else:

        lookup = CveLookup()

    cves_by_host = {}

    for host in targets:

        if lookup is None:

            cves_by_host[host.ip] = {}

        else:

            logger.info(
                "Looking up CVEs for %s...",
                host.ip,
            )

            cves_by_host[
                host.ip
            ] = lookup.lookup_for_ports(
                host.open_ports()
            )



    # -------------------------------------------------
    # 5. OpenAI analysis
    # -------------------------------------------------

    logger.info(
        "Sending scan evidence to OpenAI "
        "for analysis..."
    )

    result = analyze_hosts(
        client,
        targets,
        cves_by_host,
        args.model,
    )

    # -------------------------------------------------
    # 6. Generate output
    # -------------------------------------------------

    if args.format == "markdown":

        text = generate_markdown_report(
            Path(scan_path).name,
            hosts,
            result.findings,
            result.hallucinated_cves,
            args.model,
            datetime.now(),
        )

    else:

        text = format_terminal_table(
            result.findings
        )

    # -------------------------------------------------
    # 7. Print or save report
    # -------------------------------------------------

    if args.output:

        if args.format == "markdown":

            file_text = text

        else:

            file_text = (
                f"{LEGAL_WARNING}\n\n"
                f"{text}\n"
            )

        write_text(
            args.output,
            file_text,
        )

        print(
            f"Report saved to "
            f"{args.output}"
        )

    else:

        print(text)

    # -------------------------------------------------
    # 8. Summary
    # -------------------------------------------------

    print(
        f"\nSummary: "
        f"{summary_line(result.findings)}"
    )

    print(
        "Reminder: a human must verify "
        "every finding."
    )

    # -------------------------------------------------
    # 9. Optional JSON output
    # -------------------------------------------------

    if args.json_out:

        data = build_json_output(
            Path(scan_path).name,
            hosts,
            result.findings,
            result.hallucinated_cves,
        )

        write_text(
            args.json_out,
            json.dumps(
                data,
                indent=2,
            ),
        )

        print(
            f"Findings JSON saved to "
            f"{args.json_out}"
        )

    return EXIT_OK


def main() -> None:
    """Console entry point."""

    sys.exit(
        run()
    )


if __name__ == "__main__":
    main()
