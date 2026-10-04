from pathlib import Path

from src.cve_lookup import CveLookup, CveLookupResult, CveRecord


def test_cve_record_creation():
    record = CveRecord(
        cve_id="CVE-2024-1234",
        description="Example vulnerability description",
        severity="HIGH",
        cvss_score=7.5,
    )

    assert record.cve_id == "CVE-2024-1234"
    assert record.description == "Example vulnerability description"
    assert record.severity == "HIGH"
    assert record.cvss_score == 7.5


def test_cve_record_fields_are_stored():
    record = CveRecord(
        cve_id="CVE-2023-0001",
        description="Test vulnerability",
        severity="MEDIUM",
        cvss_score=5.0,
    )

    assert isinstance(record.cve_id, str)
    assert isinstance(record.description, str)
    assert isinstance(record.severity, str)
    assert isinstance(record.cvss_score, (int, float))


def test_cve_record_has_expected_values():
    record = CveRecord(
        cve_id="CVE-2022-9999",
        description="Another test vulnerability",
        severity="LOW",
        cvss_score=3.1,
    )

    assert record.cve_id.startswith("CVE-")
    assert record.description != ""
    assert record.severity in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN",
    }
    assert 0.0 <= record.cvss_score <= 10.0


def test_lookup_does_not_cache_failed_nvd_request(
    tmp_path: Path,
    monkeypatch,
):
    cache_file = tmp_path / "nvd_cache.json"
    lookup = CveLookup(cache_file=cache_file)

    monkeypatch.setattr(
        lookup,
        "_query_nvd",
        lambda keyword: CveLookupResult(
            records=[],
            success=False,
        ),
    )

    result = lookup.lookup(
        "OpenSSH",
        "8.2",
    )

    assert result == []
    assert "openssh 8.2" not in lookup._cache
    assert not cache_file.exists()

def test_successful_nvd_lookup_can_return_zero_cves(
    tmp_path: Path,
    monkeypatch,
):
    cache_file = tmp_path / "nvd_cache.json"
    lookup = CveLookup(cache_file=cache_file)

    monkeypatch.setattr(
        lookup,
        "_query_nvd",
        lambda keyword: CveLookupResult(
            records=[],
            success=True,
        ),
    )

    result = lookup.lookup(
        "ExampleProduct",
        "1.0",
    )

    assert result == []
    assert "exampleproduct 1.0" in lookup._cache

def test_lookup_for_ports_returns_cve_candidates(
    tmp_path: Path,
    monkeypatch,
):
    cache_file = tmp_path / "nvd_cache.json"
    lookup = CveLookup(cache_file=cache_file)

    monkeypatch.setattr(
    lookup,
    "lookup",
    lambda product, version: CveLookupResult(
        records=[
            CveRecord(
                cve_id="CVE-2024-1234",
                description="Test vulnerability",
                severity="HIGH",
                cvss_score=7.5,
            )
        ],
        success=True,
    ),
)

    class FakePort:
        number = 22
        product = "OpenSSH"
        version = "8.2"

    result = lookup.lookup_for_ports(
        [FakePort()]
    )

    assert 22 in result
    assert len(result[22]) == 1
    assert result[22][0].cve_id == "CVE-2024-1234"

def test_lookup_for_ports_with_status_reports_success(
    tmp_path: Path,
    monkeypatch,
):
    cache_file = tmp_path / "nvd_cache.json"
    lookup = CveLookup(cache_file=cache_file)

    monkeypatch.setattr(
        lookup,
        "_query_nvd",
        lambda keyword: CveLookupResult(
            records=[],
            success=True,
        ),
    )

    class FakePort:
        number = 22
        product = "OpenSSH"
        version = "8.2"

    result = lookup.lookup_for_ports_with_status(
        [FakePort()]
    )

    assert 22 in result
    assert result[22].success is True
    assert result[22].records == []

def test_lookup_for_ports_with_status_reports_failure(
    tmp_path: Path,
    monkeypatch,
):
    cache_file = tmp_path / "nvd_cache.json"
    lookup = CveLookup(cache_file=cache_file)

    monkeypatch.setattr(
        lookup,
        "_query_nvd",
        lambda keyword: CveLookupResult(
            records=[],
            success=False,
        ),
    )

    class FakePort:
        number = 22
        product = "OpenSSH"
        version = "8.2"

    result = lookup.lookup_for_ports_with_status(
        [FakePort()]
    )

    assert 22 in result
    assert result[22].success is False
    assert result[22].records == []