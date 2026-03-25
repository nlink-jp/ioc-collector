import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import stix2

from ioc_collector.models import IncidentReport, IoCEntry, IoCType, ReferenceEntry
from ioc_collector.stix_builder import StixBuilder


@pytest.fixture
def sample_report() -> IncidentReport:
    return IncidentReport(
        title="RansomwareX Campaign 2024",
        summary="A ransomware campaign.",
        timeline=["2024-01-10: Initial access"],
        affected_scope="Healthcare sector.",
        countermeasures=["Patch CVE-2024-1234"],
        iocs=[
            IoCEntry(type=IoCType.IPV4_ADDR, value="192.0.2.1", description="C2 server"),
            IoCEntry(type=IoCType.DOMAIN_NAME, value="evil.example.com"),
            IoCEntry(type=IoCType.URL, value="http://evil.example.com/payload"),
            IoCEntry(type=IoCType.FILE_HASH_MD5, value="d41d8cd98f00b204e9800998ecf8427e"),
            IoCEntry(type=IoCType.FILE_HASH_SHA1, value="da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            IoCEntry(type=IoCType.FILE_HASH_SHA256, value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            IoCEntry(type=IoCType.FILE_NAME, value="malware.exe"),
            IoCEntry(type=IoCType.PROCESS_NAME, value="svchost_fake.exe"),
            IoCEntry(type=IoCType.OTHER, value="registry key: HKLM\\Software\\Evil"),
        ],
        references=[ReferenceEntry(title="Example Report", url="https://example.com/report")],
    )


class TestBuildBundle:
    def test_returns_stix_bundle(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        assert isinstance(bundle, stix2.Bundle)

    def test_bundle_contains_report_object(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        reports = [o for o in bundle.objects if o.type == "report"]
        assert len(reports) == 1
        assert reports[0].name == sample_report.title

    def test_bundle_contains_indicators_for_each_ioc(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert len(indicators) == len(sample_report.iocs)

    def test_report_refs_all_indicators(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        report = next(o for o in bundle.objects if o.type == "report")
        indicator_ids = {i.id for i in indicators}
        assert indicator_ids == set(report.object_refs)

    def test_ioc_patterns(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        indicators = {i.name: i for i in bundle.objects if i.type == "indicator"}
        assert "[ipv4-addr:value = '192.0.2.1']" in indicators["192.0.2.1"].pattern
        assert "[domain-name:value = 'evil.example.com']" in indicators["evil.example.com"].pattern
        assert "[url:value = 'http://evil.example.com/payload']" in indicators["http://evil.example.com/payload"].pattern
        assert "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']" in indicators["d41d8cd98f00b204e9800998ecf8427e"].pattern
        assert "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']" in indicators["da39a3ee5e6b4b0d3255bfef95601890afd80709"].pattern
        assert "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']" in indicators["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].pattern
        assert "[file:name = 'malware.exe']" in indicators["malware.exe"].pattern
        assert "[process:name = 'svchost_fake.exe']" in indicators["svchost_fake.exe"].pattern

    def test_other_type_gets_generic_pattern(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        other_ind = next(
            i for i in bundle.objects
            if i.type == "indicator" and "registry key" in i.name
        )
        assert other_ind.pattern is not None

    def test_empty_iocs_bundle_has_report(self):
        report = IncidentReport(
            title="Minimal", summary=".", affected_scope="."
        )
        bundle = StixBuilder(report).build()
        reports = [o for o in bundle.objects if o.type == "report"]
        assert len(reports) == 1
        assert reports[0].name == "Minimal"
        # IoC がなくても object_refs が存在すること（STIX 2.1 必須）
        assert len(reports[0].object_refs) >= 1

    def test_defanged_ioc_is_refanged_in_pattern(self):
        """デファング済み IoC がリファングされて STIX パターンに記録されること。"""
        report = IncidentReport(
            title="Test",
            summary=".",
            affected_scope=".",
            iocs=[
                IoCEntry(type=IoCType.IPV4_ADDR, value="192.0.2[.]1"),
                IoCEntry(type=IoCType.DOMAIN_NAME, value="evil[.]example[.]com"),
                IoCEntry(type=IoCType.URL, value="hxxp://evil[.]example[.]com/path"),
            ],
        )
        bundle = StixBuilder(report).build()
        indicators = {i.name: i for i in bundle.objects if i.type == "indicator"}
        # デファング済み入力でも実値でパターンが生成されること
        assert "[ipv4-addr:value = '192.0.2.1']" in indicators["192.0.2[.]1"].pattern
        assert "[domain-name:value = 'evil.example.com']" in indicators["evil[.]example[.]com"].pattern
        assert "[url:value = 'http://evil.example.com/path']" in indicators["hxxp://evil[.]example[.]com/path"].pattern

    def test_serializes_to_valid_json(self, sample_report):
        bundle = StixBuilder(sample_report).build()
        json_str = bundle.serialize()
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) > 0


class TestSave:
    def test_saves_json_file(self, sample_report, tmp_path):
        fixed_dt = datetime(2024, 3, 25, 12, 0, 0)
        with patch("ioc_collector.stix_builder.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            saved = StixBuilder(sample_report).save(tmp_path)

        assert saved.exists()
        assert saved.suffix == ".json"
        assert saved.name == "RansomwareX_Campaign_2024_20240325_120000.json"
        data = json.loads(saved.read_text())
        assert data["type"] == "bundle"
