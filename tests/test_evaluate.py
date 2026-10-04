import json

from src.evaluate import load_json


def test_load_json_reads_valid_file(tmp_path):
    data = {
        "findings": [
            {
                "host": "192.168.1.10",
                "port": 22,
                "service": "ssh",
                "severity": "medium",
            }
        ]
    }

    test_file = tmp_path / "findings.json"
    test_file.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = load_json(str(test_file))

    assert result == data


def test_load_json_reads_empty_findings(tmp_path):
    data = {
        "findings": []
    }

    test_file = tmp_path / "empty.json"
    test_file.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = load_json(str(test_file))

    assert result == data


def test_load_json_returns_dictionary(tmp_path):
    data = {
        "findings": [],
        "hallucinated_cves": [],
    }

    test_file = tmp_path / "result.json"
    test_file.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = load_json(str(test_file))

    assert isinstance(result, dict)