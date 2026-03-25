import re
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from ioc_collector.models import IncidentReport, IoCEntry, IoCType, ReferenceEntry
from ioc_collector.report import MarkdownReport


@pytest.fixture
def sample_report() -> IncidentReport:
    return IncidentReport(
        title="RansomwareX Campaign 2024",
        summary="A ransomware campaign targeting healthcare organizations.",
        timeline=[
            "2024-01-10: Initial access via phishing",
            "2024-01-12: Ransomware deployed",
        ],
        affected_scope="Healthcare sector in North America, ~50 organizations.",
        countermeasures=["Patch CVE-2024-1234", "Block listed IPs"],
        iocs=[
            IoCEntry(type=IoCType.IPV4_ADDR, value="192.0.2.1"),
            IoCEntry(type=IoCType.DOMAIN_NAME, value="evil.example.com", description="C2 server"),
            IoCEntry(type=IoCType.FILE_HASH_MD5, value="d41d8cd98f00b204e9800998ecf8427e"),
        ],
        references=[ReferenceEntry(title="Example Security Report", url="https://example.com/report")],
    )


class TestRender:
    def test_contains_title(self, sample_report):
        md = MarkdownReport(sample_report).render()
        assert "# RansomwareX Campaign 2024" in md

    def test_contains_summary(self, sample_report):
        md = MarkdownReport(sample_report).render()
        assert sample_report.summary in md

    def test_contains_all_timeline_entries(self, sample_report):
        md = MarkdownReport(sample_report).render()
        for entry in sample_report.timeline:
            assert entry in md

    def test_iocs_are_defanged(self, sample_report):
        md = MarkdownReport(sample_report).render()
        # IP アドレスはデファング済み
        assert "192[.]0[.]2[.]1" in md
        assert "192.0.2.1" not in md
        # ドメインはデファング済み
        assert "evil[.]example[.]com" in md
        assert "evil.example.com" not in md
        # ハッシュはそのまま
        assert "d41d8cd98f00b204e9800998ecf8427e" in md
        # 型ラベルも出力される
        for ioc in sample_report.iocs:
            assert ioc.type.value in md

    def test_ioc_description_is_rendered(self, sample_report):
        md = MarkdownReport(sample_report).render()
        # evil.example.com の description "C2 server" が出力に含まれること
        assert "C2 server" in md

    def test_ioc_section_has_defang_warning(self, sample_report):
        md = MarkdownReport(sample_report).render()
        assert "デファング処理済み" in md  # ja ヘッダーに含まれる語句

    def test_contains_all_references(self, sample_report):
        md = MarkdownReport(sample_report).render()
        for ref in sample_report.references:
            assert ref.title in md
            assert ref.url in md

    def test_contains_all_countermeasures(self, sample_report):
        md = MarkdownReport(sample_report).render()
        for measure in sample_report.countermeasures:
            assert measure in md

    def test_default_language_is_japanese(self, sample_report):
        md = MarkdownReport(sample_report).render()
        assert "## インシデント概要" in md
        assert "## 参考情報" in md

    def test_english_headers(self):
        report = IncidentReport(
            title="Test",
            summary="A test.",
            affected_scope="Global.",
            timeline=["2024-01-01: event"],
            countermeasures=["patch"],
            iocs=[IoCEntry(type=IoCType.IPV4_ADDR, value="192.0.2.1")],
            references=[ReferenceEntry(title="Ref", url="https://example.com")],
        )
        md = MarkdownReport(report, language="en").render()
        assert "## Summary" in md
        assert "## Timeline" in md
        assert "## Affected Scope" in md
        assert "## Countermeasures" in md
        assert "## References" in md
        assert "インシデント概要" not in md

    def test_unknown_language_falls_back_to_english(self):
        report = IncidentReport(title="T", summary="S.", affected_scope="A.")
        md = MarkdownReport(report, language="zh").render()
        assert "## Summary" in md

    def test_empty_sections_are_omitted(self):
        report = IncidentReport(
            title="Minimal",
            summary="Minimal incident.",
            affected_scope="Unknown",
        )
        md = MarkdownReport(report).render()
        # 空リストのセクションは出力されない
        assert "## タイムライン" not in md
        assert "## IoC" not in md


class TestFilename:
    def test_filename_format(self, sample_report):
        fixed_dt = datetime(2024, 3, 25, 12, 0, 0)
        with patch("ioc_collector.report.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            name = MarkdownReport(sample_report).filename()
        assert name == "RansomwareX_Campaign_2024_20240325_120000.md"

    def test_special_chars_are_sanitized(self):
        report = IncidentReport(
            title="Incident: CVE-2024/1234 (Critical!)",
            summary=".",
            affected_scope=".",
        )
        name = MarkdownReport(report).filename()
        # スラッシュ・コロン・括弧等が含まれないこと
        assert re.match(r"^[\w\-]+\.md$", name)


class TestSave:
    def test_saves_file_to_output_dir(self, sample_report, tmp_path):
        fixed_dt = datetime(2024, 3, 25, 12, 0, 0)
        with patch("ioc_collector.report.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            saved = MarkdownReport(sample_report).save(tmp_path)

        assert saved.exists()
        assert saved.parent == tmp_path
        assert saved.name == "RansomwareX_Campaign_2024_20240325_120000.md"
        assert "# RansomwareX Campaign 2024" in saved.read_text()
