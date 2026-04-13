# ioc-collector

A CLI tool that autonomously researches security incidents from report URLs, CVE IDs, or natural language queries, and extracts structured IoC (Indicators of Compromise) data into Markdown reports and STIX 2.1 bundles.

[日本語版 README はこちら](README.ja.md)

## Features

- **Autonomous web research** — Given a URL, CVE ID, or free-text query, investigates the incident by browsing the web
- **Dual output** — Produces a human-readable Markdown report and a machine-readable STIX 2.1 JSON bundle
- **Defanged IoCs** — All indicators are defanged in the Markdown output for safe sharing
- **Multi-language output** — Reports can be generated in Japanese or English (BCP 47 codes supported)
- **Flexible input** — Accepts URL arguments, file input (`--file`), or stdin for pipeline use
- **Configurable model** — Choose any Gemini model; defaults to `gemini-2.5-flash`

## Installation

**Prerequisites:** Python 3.13+ and [uv](https://docs.astral.sh/uv/). A Google Cloud project with the Vertex AI API enabled is also required.

```bash
git clone https://github.com/nlink-jp/ioc-collector.git
cd ioc-collector
uv sync --extra dev
```

## Configuration

`ioc-collector` uses Application Default Credentials (ADC) for Google Cloud authentication.

```bash
gcloud auth application-default login
```

### Config file

Create `~/.config/ioc-collector/config.toml`:

```toml
project  = "your-project-id"
location = "us-central1"
```

See [`config.example.toml`](config.example.toml) for a full example.

### Environment variables

```bash
# Tool-specific (highest priority)
export IOC_COLLECTOR_PROJECT="your-project-id"
export IOC_COLLECTOR_LOCATION="us-central1"

# Cross-tool fallback
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="us-central1"   # optional, defaults to us-central1
```

### Priority order

env vars (`IOC_COLLECTOR_*` / `GOOGLE_CLOUD_*`) > config.toml > defaults

## Usage

```bash
# Research from a URL
uv run ioc-collector --target "https://example.com/security-incident-report"

# Research by CVE ID or natural language
uv run ioc-collector --target "CVE-2024-1234 ransomware campaign"

# Read target from a file
uv run ioc-collector --file incident_query.txt

# Read target from stdin
cat incident_query.txt | uv run ioc-collector

# Specify output directory
uv run ioc-collector --target "..." --output ./reports

# Skip confirmation prompt (for automation)
uv run ioc-collector --target "..." --non-interactive

# Specify model
uv run ioc-collector --target "..." --model gemini-2.5-pro

# Output in English
uv run ioc-collector --target "CVE-2024-1234" --language en

# Enable debug logging
uv run ioc-collector --target "..." --verbose
```

### Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--target TEXT` | `-t` | — | Research target (URL / CVE ID / natural language) |
| `--file PATH` | `-f` | — | Input file path |
| `--non-interactive` | — | `false` | Skip confirmation prompt |
| `--output DIR` | `-o` | `.` (current dir) | Output directory |
| `--model TEXT` | — | `gemini-2.5-flash` | Gemini model to use |
| `--language TEXT` | `-l` | `ja` | Output language (BCP 47: `ja`, `en`, etc.) |
| `--verbose` | `-v` | `false` | Enable debug logging |

### Output files

Each run produces two files:

| File | Contents |
|---|---|
| `{incident-name}_{datetime}.md` | Incident summary, timeline, scope, mitigations, defanged IoC list, references |
| `{incident-name}_{datetime}.json` | STIX 2.1 Bundle (`Indicator` and `Report` objects) |

### Error reference

| Error message | Cause | Resolution |
|---|---|---|
| `GOOGLE_CLOUD_PROJECT is not set` | Missing env var | Set via config file, `IOC_COLLECTOR_PROJECT`, or `GOOGLE_CLOUD_PROJECT` |
| `Authentication failed` | ADC not configured or insufficient permissions | `gcloud auth application-default login` |
| `Rate limit exceeded after retries` | API quota exceeded | Wait and retry |
| `Could not parse structured report` | Malformed Gemini output | Run with `--verbose` and retry |

## Building

```bash
# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=ioc_collector --cov-report=term-missing

# Lint / format
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

## Documentation

- [Architecture](./ARCHITECTURE.md)
- [Development rules](./AGENTS.md)
