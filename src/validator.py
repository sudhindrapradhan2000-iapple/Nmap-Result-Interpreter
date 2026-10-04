"""Validate AI findings and guard against invented CVE IDs."""

import json
import re


# Lower number = more severe.
ALLOWED_SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

SEVERITY_RANK = {
    name: index
    for index, name in enumerate(ALLOWED_SEVERITIES)
}


REQUIRED_FIELDS: dict[str, type] = {
    "port": int,
    "service": str,
    "risk": str,
    "severity": str,
    "evidence": str,
    "next_step": str,
}


CVE_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,}",
    re.IGNORECASE,
)

TEXT_FIELDS_TO_SCAN = (
    "risk",
    "evidence",
    "next_step",
)

REMOVED_MARKER = "[unverified CVE removed]"


_FENCE_PATTERN = re.compile(
    r"^```(?:json)?\s*(.*?)\s*```$",
    re.DOTALL | re.IGNORECASE,
)


class InvalidLLMOutputError(Exception):
    """Raised when the AI response is not valid expected JSON."""


def strip_code_fences(text: str) -> str:
    """Remove accidental Markdown JSON code fences."""

    stripped = text.strip()

    match = _FENCE_PATTERN.match(
        stripped
    )

    if match:
        return match.group(1).strip()

    return stripped


def _validate_one(
    item: object,
    index: int,
) -> dict:
    """Validate one AI finding."""

    if not isinstance(item, dict):
        raise InvalidLLMOutputError(
            f"Finding #{index} is not a JSON object."
        )

    missing = [
        key
        for key in REQUIRED_FIELDS
        if key not in item
    ]

    if missing:
        raise InvalidLLMOutputError(
            f"Finding #{index} is missing keys: "
            f"{', '.join(missing)}."
        )

    for key, expected_type in REQUIRED_FIELDS.items():

        value = item[key]

        # bool is technically a subclass of int in Python,
        # so explicitly reject True/False for the port.
        if expected_type is int:

            if (
                isinstance(value, bool)
                or not isinstance(value, int)
            ):
                raise InvalidLLMOutputError(
                    f"Finding #{index}: "
                    f"'{key}' must be an integer."
                )

        elif expected_type is str:

            if not isinstance(value, str):
                raise InvalidLLMOutputError(
                    f"Finding #{index}: "
                    f"'{key}' must be a string."
                )

    severity = (
        item["severity"]
        .strip()
        .lower()
    )

    if severity not in ALLOWED_SEVERITIES:
        raise InvalidLLMOutputError(
            f"Finding #{index}: severity "
            f"'{item['severity']}' must be one of "
            f"{', '.join(ALLOWED_SEVERITIES)}."
        )

    cleaned = {
        key: item[key]
        for key in REQUIRED_FIELDS
    }

    cleaned["severity"] = severity

    return cleaned


def validate_findings(
    raw_text: str,
) -> list[dict]:
    """Parse and validate the AI's JSON response."""

    cleaned_text = strip_code_fences(
        raw_text
    )

    if not cleaned_text:
        raise InvalidLLMOutputError(
            "The reply was empty."
        )

    try:

        data = json.loads(
            cleaned_text
        )

    except json.JSONDecodeError as err:

        raise InvalidLLMOutputError(
            f"The reply is not valid JSON: {err}"
        ) from err

    if (
        not isinstance(data, dict)
        or not isinstance(
            data.get("findings"),
            list,
        )
    ):
        raise InvalidLLMOutputError(
            'The top level must be a JSON object '
            'with a "findings" list.'
        )

    return [
        _validate_one(
            item,
            index,
        )
        for index, item in enumerate(
            data["findings"]
        )
    ]


def apply_hallucination_guard(
    findings: list[dict],
    allowed_cve_ids: set[str],
) -> tuple[list[dict], list[str]]:
    """Remove CVE IDs that were not supplied by our NVD lookup."""

    allowed = {
        cve_id.upper()
        for cve_id in allowed_cve_ids
    }

    hallucinated: list[str] = []
    guarded: list[dict] = []

    for finding in findings:

        removed: list[str] = []

        def scrub(
            match: re.Match,
        ) -> str:
            """Keep supplied CVEs and remove invented ones."""

            cve_id = match.group(0)

            if cve_id.upper() in allowed:
                return cve_id

            removed.append(
                cve_id.upper()
            )

            return REMOVED_MARKER

        new_finding = dict(finding)

        for field_name in TEXT_FIELDS_TO_SCAN:

            new_finding[field_name] = (
                CVE_PATTERN.sub(
                    scrub,
                    new_finding[field_name],
                )
            )

        unique_removed = sorted(
            set(removed)
        )

        new_finding[
            "removed_cves"
        ] = unique_removed

        hallucinated.extend(
            unique_removed
        )

        guarded.append(
            new_finding
        )

    return (
        guarded,
        sorted(set(hallucinated)),
    )
