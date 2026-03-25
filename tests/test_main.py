import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner

from ioc_collector.exceptions import GeminiAuthError, GeminiRateLimitError, GeminiResponseError
from ioc_collector.main import app
from ioc_collector.models import IncidentReport, IoCEntry, IoCType

runner = CliRunner()

MOCK_RESEARCH_RESULT = "Mock research result: CVE-2024-1234 analysis complete."
MOCK_REPORT = IncidentReport(
    title="Test Incident",
    summary="A test incident.",
    affected_scope="Test scope.",
    iocs=[IoCEntry(type=IoCType.IPV4_ADDR, value="192.0.2.1")],
    references=["https://example.com"],
)
MOCK_SAVED_PATH = Path("/tmp/Test_Incident_20240325_120000.md")


@pytest.fixture
def mock_gemini(monkeypatch, tmp_path):
    """GeminiResearchClient・MarkdownReport・StixBuilder をモック化する。"""
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")
    with (
        patch("ioc_collector.main.GeminiResearchClient") as mock_cls,
        patch("ioc_collector.main.MarkdownReport") as mock_md_cls,
        patch("ioc_collector.main.StixBuilder") as mock_stix_cls,
    ):
        mock_client = MagicMock()
        mock_client.research.return_value = MOCK_RESEARCH_RESULT
        mock_client.extract_report.return_value = MOCK_REPORT
        mock_cls.from_env.return_value = mock_client

        mock_md = MagicMock()
        mock_md.save.return_value = tmp_path / "Test_Incident_20240325_120000.md"
        mock_md_cls.return_value = mock_md

        mock_stix = MagicMock()
        mock_stix.save.return_value = tmp_path / "Test_Incident_20240325_120000.json"
        mock_stix_cls.return_value = mock_stix

        yield mock_cls, mock_client, mock_md_cls, mock_md


def test_app_no_input(mock_gemini):
    """入力がない場合にエラーを返すことを確認する"""
    result = runner.invoke(app, [])
    assert result.exit_code == 1
    assert "Error: No input provided." in result.stderr


def test_app_target_argument(mock_gemini):
    """--target 引数で文字列を受け付け、調査・レポート保存まで行うことを確認する"""
    _, mock_client, _, _ = mock_gemini
    target_text = "https://example.com/malware-news"
    result = runner.invoke(app, ["--target", target_text], input="y\n")

    assert result.exit_code == 0
    assert f"Target: {target_text}" in result.stdout
    assert "Starting investigation..." in result.stdout
    assert "Extracting structured report..." in result.stdout
    assert "Markdown report saved to:" in result.stdout
    assert "STIX bundle saved to:" in result.stdout
    mock_client.research.assert_called_once_with(target_text, model="gemini-2.5-flash")
    mock_client.extract_report.assert_called_once_with(MOCK_RESEARCH_RESULT, model="gemini-2.5-flash")


def test_app_file_argument(tmp_path, mock_gemini):
    """--file 引数でファイルパスを受け付けることを確認する"""
    file_content = "This is a test incident report from a file."
    input_file = tmp_path / "input.txt"
    input_file.write_text(file_content)

    result = runner.invoke(app, ["--file", str(input_file)], input="y\n")
    assert result.exit_code == 0
    assert f"File content: {file_content}" in result.stdout
    assert "Markdown report saved to:" in result.stdout
    assert "STIX bundle saved to:" in result.stdout


def test_app_stdin_input(mock_gemini):
    """標準入力からテキストを受け付けることを確認する"""
    stdin_content = "This is a test incident report from stdin."
    result = runner.invoke(app, ["--non-interactive"], input=stdin_content)
    assert result.exit_code == 0
    assert f"Stdin content: {stdin_content}" in result.stdout
    assert "Markdown report saved to:" in result.stdout
    assert "STIX bundle saved to:" in result.stdout


def test_app_interactive_confirm_yes(mock_gemini):
    """インタラクティブモードで 'y' を入力すると調査が開始されることを確認する"""
    result = runner.invoke(app, ["--target", "test-incident"], input="y\n")
    assert result.exit_code == 0
    assert "Starting investigation..." in result.stdout


def test_app_interactive_confirm_no(mock_gemini):
    """インタラクティブモードで 'n' を入力すると調査がキャンセルされることを確認する"""
    _, mock_client, _, _ = mock_gemini
    result = runner.invoke(app, ["--target", "test-incident"], input="n\n")
    assert result.exit_code == 0
    assert "Investigation cancelled." in result.stdout
    assert "Starting investigation..." not in result.stdout
    mock_client.research.assert_not_called()


def test_app_non_interactive_skips_confirm(mock_gemini):
    """--non-interactive フラグで確認プロンプトをスキップすることを確認する"""
    result = runner.invoke(app, ["--target", "test-incident", "--non-interactive"])
    assert result.exit_code == 0
    assert "Starting investigation..." in result.stdout


def test_app_missing_project_env(monkeypatch):
    """GOOGLE_CLOUD_PROJECT 未設定時にエラーを返すことを確認する"""
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    result = runner.invoke(app, ["--target", "test", "--non-interactive"])
    assert result.exit_code == 1
    assert "GOOGLE_CLOUD_PROJECT" in result.stderr


def test_app_custom_model(mock_gemini):
    """--model オプションで任意のモデルを指定できることを確認する"""
    _, mock_client, _, _ = mock_gemini
    result = runner.invoke(
        app,
        ["--target", "test-incident", "--non-interactive", "--model", "gemini-2.5-pro"],
    )
    assert result.exit_code == 0
    mock_client.research.assert_called_once_with("test-incident", model="gemini-2.5-pro")
    mock_client.extract_report.assert_called_once_with(MOCK_RESEARCH_RESULT, model="gemini-2.5-pro")


def test_app_custom_output_dir(mock_gemini, tmp_path):
    """--output オプションで出力ディレクトリを指定できることを確認する"""
    _, _, _, mock_md = mock_gemini
    result = runner.invoke(
        app,
        ["--target", "test-incident", "--non-interactive", "--output", str(tmp_path)],
    )
    assert result.exit_code == 0
    mock_md.save.assert_called_once_with(tmp_path)


class TestErrorHandling:
    def test_auth_error_shows_hint(self, mock_gemini):
        _, mock_client, _, _ = mock_gemini
        mock_client.research.side_effect = GeminiAuthError("auth failed")
        result = runner.invoke(app, ["--target", "test", "--non-interactive"])
        assert result.exit_code == 1
        assert "Authentication failed" in result.stderr
        assert "gcloud auth" in result.stderr

    def test_rate_limit_error_shows_wait_time(self, mock_gemini):
        _, mock_client, _, _ = mock_gemini
        mock_client.research.side_effect = GeminiRateLimitError("rate limited", retry_after=30)
        result = runner.invoke(app, ["--target", "test", "--non-interactive"])
        assert result.exit_code == 1
        assert "30" in result.stderr

    def test_response_error_on_extract(self, mock_gemini):
        _, mock_client, _, _ = mock_gemini
        mock_client.extract_report.side_effect = GeminiResponseError("parse failed")
        result = runner.invoke(app, ["--target", "test", "--non-interactive"])
        assert result.exit_code == 1
        assert "parse" in result.stderr.lower()

    def test_verbose_flag_accepted(self, mock_gemini):
        result = runner.invoke(app, ["--target", "test", "--non-interactive", "--verbose"])
        assert result.exit_code == 0
