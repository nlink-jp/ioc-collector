# ioc-collector

セキュリティインシデントのレポートや記事 URL を入力として、Web を自律的に調査し、IoC（Indicators of Compromise）情報を抽出・構造化する CLI ツールです。

## 出力物

実行すると2つのファイルが生成されます。

| ファイル | 内容 |
|---|---|
| `{インシデント名}_{日時}.md` | インシデント概要・タイムライン・影響範囲・対策・IoC一覧（デファング済み）・参考URL |
| `{インシデント名}_{日時}.json` | STIX 2.1 Bundle（`Indicator`・`Report` オブジェクト） |

## セットアップ

### 前提条件

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- Google Cloud プロジェクト（Vertex AI API が有効化済み）

### インストール

```bash
git clone <repository-url>
cd ioc_collector
uv sync --extra dev
```

### Google Cloud 認証

ADC（Application Default Credentials）を使用します。

```bash
gcloud auth application-default login
```

必要な環境変数を設定します。

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="us-central1"   # 省略時のデフォルト
```

## 使い方

### URL を調査する

```bash
uv run ioc-collector --target "https://example.com/security-incident-report"
```

### CVE-ID や自然言語テキストで調査する

```bash
uv run ioc-collector --target "CVE-2024-1234 に関連するランサムウェアキャンペーン"
```

### ファイルから入力する

```bash
uv run ioc-collector --file incident_query.txt
```

### 標準入力から渡す

```bash
cat incident_query.txt | uv run ioc-collector
```

### 出力ディレクトリを指定する

```bash
uv run ioc-collector --target "..." --output ./reports
```

### 確認プロンプトをスキップする（自動化用途）

```bash
uv run ioc-collector --target "..." --non-interactive
```

### モデルを指定する

```bash
uv run ioc-collector --target "..." --model gemini-2.5-pro
```

デフォルトモデルは `gemini-2.5-flash` です。

### デバッグログを有効化する

```bash
uv run ioc-collector --target "..." --verbose
```

## オプション一覧

| オプション | 短縮形 | デフォルト | 説明 |
|---|---|---|---|
| `--target TEXT` | `-t` | — | 調査対象（URL / CVE-ID / 自然言語）|
| `--file PATH` | `-f` | — | 入力ファイルパス |
| `--non-interactive` | — | `false` | 確認プロンプトをスキップ |
| `--output DIR` | `-o` | `.`（カレント）| 出力ディレクトリ |
| `--model TEXT` | — | `gemini-2.5-flash` | 使用する Gemini モデル |
| `--verbose` | `-v` | `false` | デバッグログを出力 |

## エラーへの対処

| エラーメッセージ | 原因 | 対処 |
|---|---|---|
| `GOOGLE_CLOUD_PROJECT is not set` | 環境変数未設定 | `export GOOGLE_CLOUD_PROJECT=...` |
| `Authentication failed` | ADC 未設定または権限不足 | `gcloud auth application-default login` |
| `Rate limit exceeded after retries` | API クォータ超過 | しばらく待ってから再実行 |
| `Could not parse structured report` | Gemini の出力が不正 | `--verbose` で詳細を確認し、再実行 |

## 開発者向け

### テストの実行

```bash
uv run pytest
```

### カバレッジ付きで実行

```bash
uv run pytest --cov=ioc_collector --cov-report=term-missing
```

### Lint / フォーマット

```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

## 設計・アーキテクチャ

技術的な設計判断とその根拠については [ARCHITECTURE.md](./ARCHITECTURE.md) を参照してください。

## 開発ルール

ブランチ戦略・コミット規約・セキュリティ方針については [AGENTS.md](./AGENTS.md) を参照してください。
