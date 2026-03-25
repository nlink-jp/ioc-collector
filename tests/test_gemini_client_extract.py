import json
import pytest
from unittest.mock import MagicMock, patch

from ioc_collector.gemini_client import GeminiResearchClient, DEFAULT_MODEL
from ioc_collector.models import IncidentReport, IoCType

SAMPLE_REPORT_DATA = {
    "title": "RansomwareX Campaign 2024",
    "summary": "A ransomware campaign.",
    "timeline": ["2024-01-10: Initial access"],
    "affected_scope": "Healthcare sector.",
    "countermeasures": ["Patch CVE-2024-1234"],
    "iocs": [
        {"type": "ipv4-addr", "value": "192.0.2.1", "description": ""},
        {"type": "domain-name", "value": "evil.example.com", "description": "C2 server"},
    ],
    "references": [{"title": "Example Security Report", "url": "https://example.com/report"}],
}


@pytest.fixture
def client_with_mock():
    with patch("ioc_collector.gemini_client.genai.Client") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        client = GeminiResearchClient(project="my-project", location="us-central1")
        yield client, mock_instance


class TestExtractReport:
    def test_returns_incident_report(self, client_with_mock):
        client, mock_api = client_with_mock
        mock_api.models.generate_content.return_value = MagicMock(
            text=json.dumps(SAMPLE_REPORT_DATA)
        )

        report = client.extract_report("raw research text")

        assert isinstance(report, IncidentReport)
        assert report.title == "RansomwareX Campaign 2024"
        assert len(report.iocs) == 2
        assert report.iocs[0].type == IoCType.IPV4_ADDR
        assert report.iocs[0].value == "192.0.2.1"

    def test_uses_response_schema(self, client_with_mock):
        client, mock_api = client_with_mock
        mock_api.models.generate_content.return_value = MagicMock(
            text=json.dumps(SAMPLE_REPORT_DATA)
        )

        client.extract_report("raw research text")

        call_kwargs = mock_api.models.generate_content.call_args.kwargs
        config = call_kwargs["config"]
        assert config.response_schema is IncidentReport
        assert config.response_mime_type == "application/json"

    def test_does_not_use_google_search_tool(self, client_with_mock):
        client, mock_api = client_with_mock
        mock_api.models.generate_content.return_value = MagicMock(
            text=json.dumps(SAMPLE_REPORT_DATA)
        )

        client.extract_report("raw research text")

        call_kwargs = mock_api.models.generate_content.call_args.kwargs
        config = call_kwargs["config"]
        # Grounding ツールは使わない
        assert not config.tools

    def test_uses_default_model(self, client_with_mock):
        client, mock_api = client_with_mock
        mock_api.models.generate_content.return_value = MagicMock(
            text=json.dumps(SAMPLE_REPORT_DATA)
        )

        client.extract_report("raw research text")

        call_kwargs = mock_api.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == DEFAULT_MODEL

    def test_custom_model(self, client_with_mock):
        client, mock_api = client_with_mock
        mock_api.models.generate_content.return_value = MagicMock(
            text=json.dumps(SAMPLE_REPORT_DATA)
        )

        client.extract_report("raw research text", model="gemini-2.5-pro")

        call_kwargs = mock_api.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == "gemini-2.5-pro"
