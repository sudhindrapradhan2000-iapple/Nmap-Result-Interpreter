"""NVD CVE candidate lookup for the Nmap Result Interpreter.

Important:
NVD keyword results are only candidate vulnerabilities.
They are NOT treated as confirmed vulnerabilities.
"""

import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import requests

from src.parser import Port

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REQUEST_TIMEOUT_SECONDS = 10
RESULTS_PER_PAGE = 5

# NVD request pacing.
DELAY_WITHOUT_KEY = 6.0
DELAY_WITH_KEY = 0.7

CACHE_FILE = Path(".cache") / "nvd_cache.json"

MAX_DESCRIPTION_CHARS = 300

RATE_LIMIT_STATUS_CODES = (403, 429)


@dataclass
class CveRecord:
    """One CVE candidate returned by NVD."""

    cve_id: str
    description: str
    cvss_score: float | None
    severity: str

@dataclass
class CveLookupResult:
    """Result of an NVD lookup, including whether the request succeeded."""

    records: list[CveRecord]
    success: bool


def _english_description(descriptions: list[dict]) -> str:
    """Return the English CVE description."""

    for item in descriptions:
        if item.get("lang") == "en":
            return str(
                item.get("value", "")
            )[:MAX_DESCRIPTION_CHARS]

    return ""


def _best_cvss(
    metrics: dict,
) -> tuple[float | None, str]:
    """Return the best available CVSS score and severity."""

    for metric_name in (
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        metric_list = metrics.get(metric_name)

        if not metric_list:
            continue

        first = metric_list[0]

        cvss_data = first.get(
            "cvssData",
            {},
        )

        score = cvss_data.get("baseScore")

        severity = (
            cvss_data.get("baseSeverity")
            or first.get("baseSeverity")
            or ""
        )

        if score is not None:
            return (
                float(score),
                str(severity).lower() or "unknown",
            )

    return None, "unknown"


def _parse_nvd_response(
    data: dict,
) -> list[CveRecord]:
    """Convert NVD JSON into CveRecord objects."""

    records: list[CveRecord] = []

    for item in data.get(
        "vulnerabilities",
        [],
    ):
        cve = item.get(
            "cve",
            {},
        )

        cve_id = cve.get("id")

        if not cve_id:
            continue

        score, severity = _best_cvss(
            cve.get(
                "metrics",
                {},
            )
        )

        records.append(
            CveRecord(
                cve_id=str(cve_id),
                description=_english_description(
                    cve.get(
                        "descriptions",
                        [],
                    )
                ),
                cvss_score=score,
                severity=severity,
            )
        )

    # Highest CVSS first.
    records.sort(
        key=lambda record: record.cvss_score or 0.0,
        reverse=True,
    )

    return records


class CveLookup:
    """NVD client with memory and disk caching."""

    def __init__(
        self,
        cache_file: Path = CACHE_FILE,
        timeout: int = REQUEST_TIMEOUT_SECONDS,
    ) -> None:

        self.cache_file = cache_file
        self.timeout = timeout

        # Optional NVD API key.
        self._api_key = os.environ.get(
            "NVD_API_KEY",
            "",
        ).strip()

        self._delay = (
            DELAY_WITH_KEY
            if self._api_key
            else DELAY_WITHOUT_KEY
        )

        self._last_request_time: float | None = None

        self._cache: dict[
            str,
            list[dict],
        ] = self._load_cache()

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(
        self,
    ) -> dict[str, list[dict]]:
        """Load the local CVE cache."""

        if not self.cache_file.is_file():
            return {}

        try:
            data = json.loads(
                self.cache_file.read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
        ) as err:

            logger.warning(
                "Ignoring unreadable CVE cache: %s",
                err,
            )

            return {}

        return (
            data
            if isinstance(data, dict)
            else {}
        )

    def _save_cache(self) -> None:
        """Save the CVE cache to disk."""

        try:
            self.cache_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self.cache_file.write_text(
                json.dumps(
                    self._cache,
                    indent=2,
                ),
                encoding="utf-8",
            )

        except OSError as err:

            logger.warning(
                "Could not save CVE cache: %s",
                err,
            )

    # ------------------------------------------------------------------
    # NVD request handling
    # ------------------------------------------------------------------

    def _wait_for_rate_limit(self) -> None:
        """Wait between NVD requests."""

        if self._last_request_time is None:
            return

        elapsed = (
            time.monotonic()
            - self._last_request_time
        )

        if elapsed < self._delay:
            time.sleep(
                self._delay - elapsed
            )

    def _query_nvd(
        self,
        keyword: str,
    ) -> CveLookupResult:

        """Query NVD for candidate CVEs."""

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": RESULTS_PER_PAGE,
        }

        headers = (
            {"apiKey": self._api_key}
            if self._api_key
            else {}
        )

        self._wait_for_rate_limit()

        self._last_request_time = time.monotonic()

        try:
            response = requests.get(
                NVD_URL,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )

        except requests.exceptions.Timeout:

            logger.warning(
                "NVD request timed out for '%s'.",
                keyword,
            )

            return CveLookupResult(
                records=[],
                success=False,
            )

        except requests.exceptions.RequestException as err:

            logger.warning(
                "NVD request failed for '%s' (%s).",
                keyword,
                type(err).__name__,
            )

            return CveLookupResult(
                records=[],
                success=False,
            )

        if response.status_code in RATE_LIMIT_STATUS_CODES:

            logger.warning(
                "NVD rate limit hit (HTTP %s).",
                response.status_code,
            )

            return CveLookupResult(
                records=[],
                success=False,
            )

        if not response.ok:

            logger.warning(
                "NVD returned HTTP %s for '%s'.",
                response.status_code,
                keyword,
            )

            return CveLookupResult(
                records=[],
                success=False,
            )


        try:

            return CveLookupResult(
                records=_parse_nvd_response(
                    response.json()
                ),
                success=True,
            )

        except (
            ValueError,
            AttributeError,
            TypeError,
            KeyError,
        ) as err:

            logger.warning(
                "Unexpected NVD response for '%s' (%s).",
                keyword,
                type(err).__name__,
            )

            return CveLookupResult(
                records=[],
                success=False,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(
        self,
        product: str,
        version: str,
    ) -> list[CveRecord]:
        """Return candidate CVEs for a product and version."""

        # Don't perform a broad search if product/version is missing.
        if not product or not version:
            return []

        # Use the first version token.
        version_token = version.split()[0]

        keyword = f"{product} {version_token}"

        cache_key = keyword.lower()

        # Check cache first.
        if cache_key in self._cache:

            logger.info(
                "CVE cache hit for '%s'.",
                keyword,
            )

            try:

                return CveLookupResult(
                    records=[
                        CveRecord(**entry)
                        for entry in self._cache[
                            cache_key
                        ]
                    ],
                    success=True,
                )

            except TypeError:

                logger.warning(
                    "Bad cache entry for '%s'.",
                    keyword,
                )

        logger.info(
            "Asking NVD about '%s'...",
            keyword,
        )

        result = self._query_nvd(
            keyword
        )

        # If the request failed, don't cache the failure.
        if not result.success:
            return []

        records = result.records

        self._cache[cache_key] = [
            asdict(record)
            for record in records
        ]

        self._save_cache()

        return records

    def lookup_for_ports(
        self,
        ports: list[Port],
    ) -> dict[int, list[CveRecord]]:
        """Return CVE candidates grouped by port number."""

        results: dict[int, list[CveRecord]] = {}

        for port in ports:
            result = self.lookup(
                port.product,
                port.version,
            )

            if result.success:
                results[port.number] = result.records
            else:
                results[port.number] = []

        return results


    def lookup_for_ports_with_status(
        self,
        ports: list[Port],
    ) -> dict[int, CveLookupResult]:
        """Return NVD lookup results with success status."""

        results: dict[int, CveLookupResult] = {}

        for port in ports:

            if not port.product or not port.version:
                results[port.number] = CveLookupResult(
                    records=[],
                    success=True,
                )
                continue

            version_token = port.version.split()[0]
            keyword = f"{port.product} {version_token}"
            cache_key = keyword.lower()

            if cache_key in self._cache:

                try:
                    records = [
                        CveRecord(**entry)
                        for entry in self._cache[
                            cache_key
                        ]
                    ]

                    results[port.number] = CveLookupResult(
                        records=records,
                        success=True,
                    )

                    continue

                except TypeError:

                    logger.warning(
                        "Bad cache entry for '%s'.",
                        keyword,
                    )

            logger.info(
                "Asking NVD about '%s'...",
                keyword,
            )

            result = self._query_nvd(
                keyword
            )

            results[port.number] = result

            if result.success:

                self._cache[cache_key] = [
                    asdict(record)
                    for record in result.records
                ]

                self._save_cache()

        return results
