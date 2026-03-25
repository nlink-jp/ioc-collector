import logging
import sys
from typing import Optional
from pathlib import Path

import typer
from rich.console import Console

from ioc_collector.exceptions import (
    GeminiAuthError,
    GeminiRateLimitError,
    GeminiResponseError,
    GeminiAPIError,
)
from ioc_collector.gemini_client import GeminiResearchClient
from ioc_collector.report import MarkdownReport
from ioc_collector.stix_builder import StixBuilder

app = typer.Typer(
    name="ioc-collector",
    help="Collect and structure IoC information from security incident reports.",
)

logger = logging.getLogger(__name__)
_console = Console(stderr=True)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def main(
    target: Optional[str] = typer.Option(
        None, "-t", "--target",
        help="Target URL, CVE-ID, or natural language text about the incident.",
    ),
    file: Optional[Path] = typer.Option(
        None, "-f", "--file",
        exists=True, file_okay=True, dir_okay=False,
        writable=False, readable=True, resolve_path=True,
        help="Path to a file containing incident information.",
    ),
    non_interactive: bool = typer.Option(
        False, "--non-interactive",
        help="Skip interactive confirmation before starting investigation.",
    ),
    output: Path = typer.Option(
        Path("."), "-o", "--output",
        file_okay=False, dir_okay=True, writable=True, resolve_path=True,
        help="Directory to save output files (default: current directory).",
    ),
    model: str = typer.Option(
        "gemini-2.5-flash", "--model",
        help="Gemini model ID to use for research.",
    ),
    language: str = typer.Option(
        "ja", "-l", "--language",
        help="Output language as a BCP 47 code (e.g. ja, en). Default: ja.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging.",
    ),
) -> None:
    """Investigate a security incident and extract IoC information."""

    _setup_logging(verbose)

    # --- 入力の取得 ---
    input_content: Optional[str] = None

    if target:
        input_content = target
        typer.echo(f"Target: {input_content}")
    elif file:
        input_content = file.read_text()
        typer.echo(f"File content: {input_content}")
    elif not sys.stdin.isatty():
        input_content = sys.stdin.read().strip()
        if input_content:
            typer.echo(f"Stdin content: {input_content}")

    if not input_content:
        typer.echo(
            "Error: No input provided. Use --target, --file, or pipe content to stdin.",
            err=True,
        )
        raise typer.Exit(code=1)

    # --- インタラクティブ確認 ---
    if not non_interactive:
        summary = input_content[:50] + ("..." if len(input_content) > 50 else "")
        confirmed = typer.confirm(f"Confirm investigation on '{summary}'?", default=True)
        if not confirmed:
            typer.echo("Investigation cancelled.")
            raise typer.Exit()

    # --- Gemini クライアントの初期化 ---
    try:
        client = GeminiResearchClient.from_env()
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    # --- 調査実行 ---
    typer.echo("Starting investigation...")
    try:
        with _console.status("Searching the web for incident information..."):
            research_text = client.research(input_content, model=model, language=language)
    except GeminiAuthError as e:
        typer.echo(f"Error: Authentication failed. {e}", err=True)
        typer.echo("Hint: Run `gcloud auth application-default login`", err=True)
        raise typer.Exit(code=1)
    except GeminiRateLimitError as e:
        typer.echo(
            f"Error: Rate limit exceeded after retries. "
            f"Wait {e.retry_after} seconds and try again.",
            err=True,
        )
        raise typer.Exit(code=1)
    except GeminiAPIError as e:
        typer.echo(f"Error: Gemini API error during research: {e}", err=True)
        raise typer.Exit(code=1)
    typer.echo("Web search complete.")

    # --- 構造化抽出 ---
    typer.echo("Extracting structured report...")
    try:
        with _console.status("Analyzing research results and extracting IoCs..."):
            report = client.extract_report(research_text, model=model, language=language)
    except GeminiRateLimitError as e:
        typer.echo(
            f"Error: Rate limit exceeded after retries. "
            f"Wait {e.retry_after} seconds and try again.",
            err=True,
        )
        raise typer.Exit(code=1)
    except GeminiResponseError as e:
        typer.echo(f"Error: Could not parse structured report from Gemini. {e}", err=True)
        raise typer.Exit(code=1)
    except GeminiAPIError as e:
        typer.echo(f"Error: Gemini API error during extraction: {e}", err=True)
        raise typer.Exit(code=1)
    typer.echo("Extraction complete.")

    # --- Markdown 保存 ---
    md_report = MarkdownReport(report, language=language)
    saved_md = md_report.save(output)
    typer.echo(f"Markdown report saved to: {saved_md}")

    # --- STIX 2.1 JSON 保存 ---
    stix_report = StixBuilder(report)
    saved_stix = stix_report.save(output)
    typer.echo(f"STIX bundle saved to: {saved_stix}")


if __name__ == "__main__":
    app()
