import json
import pytest
from pydantic import ValidationError

from ioc_collector.models import IncidentReport, IoCEntry, IoCType, ReferenceEntry


def _sample_ioc(ioc_type: IoCType = IoCType.IPV4_ADDR, value: str = "192.0.2.1") -> dict:
    return {"type": ioc_type.value, "value": value}


def _valid_data() -> dict:
    return {
        "title": "RansomwareX Campaign 2024",
        "summary": "A ransomware campaign targeting healthcare organizations.",
        "timeline": ["2024-01-10: Initial access via phishing", "2024-01-12: Ransomware deployed"],
        "affected_scope": "Healthcare sector in North America, ~50 organizations.",
        "countermeasures": ["Patch CVE-2024-1234", "Block listed IPs"],
        "iocs": [
            _sample_ioc(IoCType.IPV4_ADDR, "192.0.2.1"),
            _sample_ioc(IoCType.DOMAIN_NAME, "evil.example.com"),
            _sample_ioc(IoCType.FILE_HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        ],
        "references": [
        {"title": "Example Security Report", "url": "https://example.com/report"},
        {"title": "NVD CVE-2024-1234", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
    ],
    }


class TestIoCType:
    def test_all_expected_types_exist(self):
        expected = {
            "ipv4-addr", "domain-name", "url",
            "file-hash-md5", "file-hash-sha1", "file-hash-sha256",
            "file-name", "process-name", "other",
        }
        assert {t.value for t in IoCType} == expected


class TestIoCEntry:
    def test_valid_entry(self):
        entry = IoCEntry(type=IoCType.IPV4_ADDR, value="192.0.2.1")
        assert entry.type == IoCType.IPV4_ADDR
        assert entry.value == "192.0.2.1"
        assert entry.description == ""

    def test_with_description(self):
        entry = IoCEntry(type=IoCType.DOMAIN_NAME, value="evil.example.com", description="C2 server")
        assert entry.description == "C2 server"

    def test_type_from_string(self):
        entry = IoCEntry(type="ipv4-addr", value="192.0.2.1")
        assert entry.type == IoCType.IPV4_ADDR

    def test_invalid_type_raises(self):
        with pytest.raises(ValidationError):
            IoCEntry(type="invalid-type", value="192.0.2.1")


class TestIncidentReport:
    def test_valid_incident_report(self):
        report = IncidentReport(**_valid_data())
        assert report.title == "RansomwareX Campaign 2024"
        assert len(report.timeline) == 2
        assert len(report.iocs) == 3
        assert all(isinstance(ioc, IoCEntry) for ioc in report.iocs)

    def test_empty_lists_are_allowed(self):
        data = _valid_data()
        data["timeline"] = []
        data["iocs"] = []
        data["countermeasures"] = []
        data["references"] = []
        report = IncidentReport(**data)
        assert report.iocs == []

    def test_missing_required_field_raises(self):
        data = _valid_data()
        del data["title"]
        with pytest.raises(ValidationError):
            IncidentReport(**data)

    def test_from_json(self):
        data = _valid_data()
        report = IncidentReport.model_validate_json(json.dumps(data))
        assert report.title == data["title"]
        assert report.iocs[0].type == IoCType.IPV4_ADDR
