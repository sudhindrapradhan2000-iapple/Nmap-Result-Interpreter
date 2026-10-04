import json

import pytest

from src.validator import InvalidLLMOutputError, validate_findings


def test_valid_finding_passes():
    payload = {
        "findings": [
            {
                "port": 22,
                "service": "ssh",
                "severity": "medium",
                "title": "SSH service exposed",
                "risk": "Remote administration is reachable.",
                "evidence": "Nmap identifies OpenSSH on TCP port 22.",
                "next_step": "Verify the SSH configuration and restrict access.",
            }
        ]
    }

    findings = validate_findings(json.dumps(payload))

    assert len(findings) == 1
    assert findings[0]["port"] == 22
    assert findings[0]["service"] == "ssh"
    assert findings[0]["severity"] == "medium"


def test_missing_required_field_fails():
    payload = {
        "findings": [
            {
                "port": 22,
                "service": "ssh",
                "severity": "medium",
                "title": "SSH service exposed",
                "evidence": "Nmap identifies OpenSSH on TCP port 22.",
                "next_step": "Verify the SSH configuration.",
            }
        ]
    }

    with pytest.raises(InvalidLLMOutputError):
        validate_findings(json.dumps(payload))


def test_invalid_severity_fails():
    payload = {
        "findings": [
            {
                "port": 22,
                "service": "ssh",
                "severity": "extreme",
                "title": "SSH service exposed",
                "risk": "Remote administration is reachable.",
                "evidence": "Nmap identifies OpenSSH on TCP port 22.",
                "next_step": "Verify the SSH configuration.",
            }
        ]
    }

    with pytest.raises(InvalidLLMOutputError):
        validate_findings(json.dumps(payload))