# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] - 2026-03-25

### Added

- `--language`/`-l` option to specify report output language as a BCP 47 code (default: `ja`)
  - Affects both Gemini system instructions and Markdown section headers (`ja`/`en`, English fallback for others)

### Fixed

- Reference URLs in reports were showing Vertex AI redirect URLs (`vertexaisearch.cloud.google.com`) instead of original source URLs
  - Real source URLs are now extracted from grounding metadata and appended to the research text
  - `extract_report()` is instructed to prefer grounding sources and exclude redirect URLs
- Report generation timestamp was displayed without timezone information
  - Changed to local timezone-aware format (e.g., `2026-03-25 15:31:40 JST`)

### Changed

- STIX 2.1 JSON output now uses `ensure_ascii=False` for human-readable non-ASCII characters
- References field changed from `list[str]` to `list[ReferenceEntry(title, url)]`; Markdown renders as `[title](url)` clickable links
- Progress display improved with Rich spinner during API calls

---

## [0.1.0] - 2026-03-25

### Added

- CLI tool (`ioc-collector`) for researching security incidents and extracting IoCs
- Two-stage Gemini pipeline:
  - `research()`: Web research via Google Search Grounding (Vertex AI)
  - `extract_report()`: Structured extraction using `response_schema` (Pydantic)
- Support for 9 IoC types: `ipv4-addr`, `domain-name`, `url`, `file-hash-md5`, `file-hash-sha1`, `file-hash-sha256`, `file-name`, `process-name`, `other`
- Markdown report output with defanged IoC values and clickable reference links (`[title](url)`)
- STIX 2.1 Bundle output with refanged IoC values and proper STIX patterns
- Defang/refang module with idempotent conversion (handles pre-defanged input from web articles)
- HTTP 429 exponential backoff retry (base 2s, max 60s, up to 5 retries)
- ADC (Application Default Credentials) authentication via Vertex AI
- CLI options: `--target`, `--file`, stdin, `--non-interactive`, `--output`, `--model`, `--verbose`
- Custom exception hierarchy: `GeminiAuthError`, `GeminiRateLimitError`, `GeminiResponseError`
- Rich spinner progress display during API calls
- Prompt injection countermeasures (input/instruction separation, role anchoring, schema validation)
- Full unit test suite (99 tests, all mocked — no API calls required)

### Technical notes

- Default model: `gemini-2.5-flash`
- STIX JSON output uses `ensure_ascii=False` for human-readable non-ASCII characters
- `OTHER` type IoCs use `pattern_type="sigma"` as a STIX validator workaround

[0.1.1]: https://github.com/magifd2/ioc-collector/releases/tag/v0.1.1
[0.1.0]: https://github.com/magifd2/ioc-collector/releases/tag/v0.1.0
