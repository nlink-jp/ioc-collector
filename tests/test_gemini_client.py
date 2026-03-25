import pytest
from unittest.mock import MagicMock, patch

from ioc_collector.gemini_client import GeminiResearchClient, DEFAULT_LOCATION, DEFAULT_MODEL


@pytest.fixture
def mock_genai_client():
    with patch("ioc_collector.gemini_client.genai.Client") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_cls, mock_instance


class TestFromEnv:
    def test_success(self, monkeypatch, mock_genai_client):
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "my-project")
        monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "asia-northeast1")

        client = GeminiResearchClient.from_env()

        assert client.project == "my-project"
        assert client.location == "asia-northeast1"

    def test_default_location(self, monkeypatch, mock_genai_client):
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "my-project")
        monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)

        client = GeminiResearchClient.from_env()

        assert client.location == DEFAULT_LOCATION

    def test_missing_project_raises(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

        with pytest.raises(ValueError, match="GOOGLE_CLOUD_PROJECT"):
            GeminiResearchClient.from_env()


class TestInit:
    def test_creates_vertex_ai_client(self, mock_genai_client):
        mock_cls, _ = mock_genai_client

        GeminiResearchClient(project="my-project", location="us-central1")

        mock_cls.assert_called_once_with(
            vertexai=True,
            project="my-project",
            location="us-central1",
        )


class TestResearch:
    def test_returns_response_text(self, mock_genai_client):
        _, mock_instance = mock_genai_client
        mock_response = MagicMock()
        mock_response.text = "Incident research result text"
        mock_instance.models.generate_content.return_value = mock_response

        client = GeminiResearchClient(project="my-project", location="us-central1")
        result = client.research("CVE-2024-1234 ransomware incident")

        assert result == "Incident research result text"

    def test_calls_generate_content_with_search_tool(self, mock_genai_client):
        from google.genai import types

        _, mock_instance = mock_genai_client
        mock_instance.models.generate_content.return_value = MagicMock(text="result")

        client = GeminiResearchClient(project="my-project", location="us-central1")
        client.research("test query")

        call_kwargs = mock_instance.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == DEFAULT_MODEL
        assert call_kwargs["contents"] == "test query"
        config = call_kwargs["config"]
        # Google Search ツールが含まれていることを確認
        assert any(
            tool.google_search is not None
            for tool in config.tools
        )

    def test_custom_model(self, mock_genai_client):
        _, mock_instance = mock_genai_client
        mock_instance.models.generate_content.return_value = MagicMock(text="result")

        client = GeminiResearchClient(project="my-project", location="us-central1")
        client.research("test query", model="gemini-2.5-pro")

        call_kwargs = mock_instance.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == "gemini-2.5-pro"

    def test_language_included_in_system_instruction(self, mock_genai_client):
        _, mock_instance = mock_genai_client
        mock_instance.models.generate_content.return_value = MagicMock(text="result")

        client = GeminiResearchClient(project="my-project", location="us-central1")
        client.research("test query", language="en")

        config = mock_instance.models.generate_content.call_args.kwargs["config"]
        assert "en" in config.system_instruction

    def test_default_language_is_japanese(self, mock_genai_client):
        _, mock_instance = mock_genai_client
        mock_instance.models.generate_content.return_value = MagicMock(text="result")

        client = GeminiResearchClient(project="my-project", location="us-central1")
        client.research("test query")

        config = mock_instance.models.generate_content.call_args.kwargs["config"]
        assert "ja" in config.system_instruction
