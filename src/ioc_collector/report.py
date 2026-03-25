"""Markdown レポートの生成・保存。"""

import re
from datetime import datetime
from pathlib import Path

from ioc_collector.defang import defang
from ioc_collector.models import IncidentReport

_HEADERS: dict[str, dict[str, str]] = {
    "ja": {
        "summary": "インシデント概要",
        "timeline": "タイムライン",
        "affected_scope": "影響範囲",
        "countermeasures": "対策",
        "iocs": "IoC (Indicators of Compromise)",
        "references": "参考情報",
        "defang_warning": "IoC 値はデファング処理済みです。実際の値として使用する際はデファングを解除してください。",
    },
    "en": {
        "summary": "Summary",
        "timeline": "Timeline",
        "affected_scope": "Affected Scope",
        "countermeasures": "Countermeasures",
        "iocs": "IoC (Indicators of Compromise)",
        "references": "References",
        "defang_warning": "IoC values are defanged. Refang before use in detection tools.",
    },
}


def _get_headers(language: str) -> dict[str, str]:
    return _HEADERS.get(language, _HEADERS["en"])


def _sanitize_filename(text: str) -> str:
    """タイトルをファイル名として安全な文字列に変換する。"""
    # 英数字・ハイフン・アンダースコア以外はアンダースコアに置換
    sanitized = re.sub(r"[^\w\-]", "_", text)
    # 連続するアンダースコアを1つにまとめる
    sanitized = re.sub(r"_+", "_", sanitized)
    return sanitized.strip("_")


class MarkdownReport:
    """IncidentReport を Markdown 形式に変換し、ファイルに保存するクラス。"""

    def __init__(self, report: IncidentReport, language: str = "ja") -> None:
        self._report = report
        self._h = _get_headers(language)

    def render(self) -> str:
        """Markdown 文字列を生成して返す。"""
        r = self._report
        lines: list[str] = []

        lines.append(f"# {r.title}")
        lines.append("")
        lines.append(f"**生成日時:** {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
        lines.append("")

        lines.append(f"## {self._h['summary']}")
        lines.append("")
        lines.append(r.summary)
        lines.append("")

        if r.timeline:
            lines.append(f"## {self._h['timeline']}")
            lines.append("")
            for entry in r.timeline:
                lines.append(f"- {entry}")
            lines.append("")

        lines.append(f"## {self._h['affected_scope']}")
        lines.append("")
        lines.append(r.affected_scope)
        lines.append("")

        if r.countermeasures:
            lines.append(f"## {self._h['countermeasures']}")
            lines.append("")
            for measure in r.countermeasures:
                lines.append(f"- {measure}")
            lines.append("")

        if r.iocs:
            lines.append(f"## {self._h['iocs']}")
            lines.append("")
            lines.append(f"> **Note:** {self._h['defang_warning']}")
            lines.append("")
            for ioc in r.iocs:
                safe_value = defang(ioc.value, ioc.type)
                desc = f" — {ioc.description}" if ioc.description else ""
                lines.append(f"- `{safe_value}` ({ioc.type.value}){desc}")
            lines.append("")

        if r.references:
            lines.append(f"## {self._h['references']}")
            lines.append("")
            for ref in r.references:
                if ref.url:
                    lines.append(f"- [{ref.title}]({ref.url})")
                else:
                    lines.append(f"- {ref.title}")
            lines.append("")

        return "\n".join(lines)

    def filename(self) -> str:
        """出力ファイル名を返す（形式: {title}_{yyyymmdd_hhmmss}.md）。"""
        safe_title = _sanitize_filename(self._report.title)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe_title}_{timestamp}.md"

    def save(self, output_dir: Path) -> Path:
        """指定ディレクトリに Markdown ファイルを保存し、保存先 Path を返す。"""
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / self.filename()
        path.write_text(self.render(), encoding="utf-8")
        return path
