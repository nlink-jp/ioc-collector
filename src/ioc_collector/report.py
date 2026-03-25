"""Markdown レポートの生成・保存。"""

import re
from datetime import datetime
from pathlib import Path

from ioc_collector.defang import defang
from ioc_collector.models import IncidentReport


def _sanitize_filename(text: str) -> str:
    """タイトルをファイル名として安全な文字列に変換する。"""
    # 英数字・ハイフン・アンダースコア以外はアンダースコアに置換
    sanitized = re.sub(r"[^\w\-]", "_", text)
    # 連続するアンダースコアを1つにまとめる
    sanitized = re.sub(r"_+", "_", sanitized)
    return sanitized.strip("_")


class MarkdownReport:
    """IncidentReport を Markdown 形式に変換し、ファイルに保存するクラス。"""

    def __init__(self, report: IncidentReport) -> None:
        self._report = report

    def render(self) -> str:
        """Markdown 文字列を生成して返す。"""
        r = self._report
        lines: list[str] = []

        lines.append(f"# {r.title}")
        lines.append("")
        lines.append(f"**生成日時:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("## インシデント概要")
        lines.append("")
        lines.append(r.summary)
        lines.append("")

        if r.timeline:
            lines.append("## タイムライン")
            lines.append("")
            for entry in r.timeline:
                lines.append(f"- {entry}")
            lines.append("")

        lines.append("## 影響範囲")
        lines.append("")
        lines.append(r.affected_scope)
        lines.append("")

        if r.countermeasures:
            lines.append("## 対策")
            lines.append("")
            for measure in r.countermeasures:
                lines.append(f"- {measure}")
            lines.append("")

        if r.iocs:
            lines.append("## IoC (Indicators of Compromise)")
            lines.append("")
            lines.append(
                "> **注意:** IoC 値はデファング処理済みです。"
                " 実際の値として使用する際はデファングを解除してください。"
            )
            lines.append("")
            for ioc in r.iocs:
                safe_value = defang(ioc.value, ioc.type)
                desc = f" — {ioc.description}" if ioc.description else ""
                lines.append(f"- `{safe_value}` ({ioc.type.value}){desc}")
            lines.append("")

        if r.references:
            lines.append("## 参考情報")
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
