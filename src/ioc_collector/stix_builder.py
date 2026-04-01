"""STIX 2.1 Bundle のビルダー。IncidentReport を STIX 形式に変換する。"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import stix2

from ioc_collector.defang import refang
from ioc_collector.models import IncidentReport, IoCEntry, IoCType

logger = logging.getLogger(__name__)


def _sanitize_filename(text: str) -> str:
    sanitized = re.sub(r"[^\w\-]", "_", text)
    return re.sub(r"_+", "_", sanitized).strip("_")


def _ioc_to_pattern(ioc: IoCEntry) -> str:
    """IoCEntry を STIX 2.1 パターン文字列に変換する。

    デファング表記を解除した実値を使用する。
    """
    v = refang(ioc.value).strip().replace("\\", "\\\\").replace("'", "")
    match ioc.type:
        case IoCType.IPV4_ADDR:
            return f"[ipv4-addr:value = '{v}']"
        case IoCType.DOMAIN_NAME:
            return f"[domain-name:value = '{v}']"
        case IoCType.URL:
            return f"[url:value = '{v}']"
        case IoCType.FILE_HASH_MD5:
            return f"[file:hashes.MD5 = '{v}']"
        case IoCType.FILE_HASH_SHA1:
            return f"[file:hashes.'SHA-1' = '{v}']"
        case IoCType.FILE_HASH_SHA256:
            return f"[file:hashes.'SHA-256' = '{v}']"
        case IoCType.FILE_NAME:
            return f"[file:name = '{v}']"
        case IoCType.PROCESS_NAME:
            return f"[process:name = '{v}']"
        case _:
            # OTHER: STIX パターンに収まらない自由形式値は sigma 形式で格納
            return v


def _build_indicator(ioc: IoCEntry) -> stix2.Indicator:
    desc = ioc.description or f"{ioc.type.value}: {ioc.value}"
    # OTHER 型は STIX パターン構文に収まらないため sigma 形式で格納
    is_other = ioc.type == IoCType.OTHER
    return stix2.Indicator(
        name=ioc.value,
        description=desc,
        indicator_types=["malicious-activity"],
        pattern=_ioc_to_pattern(ioc),
        pattern_type="sigma" if is_other else "stix",
        valid_from=datetime.now(timezone.utc),
    )


class StixBuilder:
    """IncidentReport から STIX 2.1 Bundle を構築するクラス。"""

    def __init__(self, report: IncidentReport) -> None:
        self._report = report

    def build(self) -> stix2.Bundle:
        """STIX 2.1 Bundle を生成して返す。"""
        indicators: list[stix2.Indicator] = []
        for ioc in self._report.iocs:
            try:
                indicators.append(_build_indicator(ioc))
            except stix2.exceptions.InvalidValueError as e:
                logger.warning(
                    "Skipping IoC (type=%s, value=%s): %s",
                    ioc.type.value, ioc.value, e,
                )

        extra_objects: list = []
        if indicators:
            object_refs = [i.id for i in indicators]
        else:
            # IoC がない場合は Identity プレースホルダーを参照として使用
            placeholder = stix2.Identity(
                name="Unknown",
                identity_class="unknown",
            )
            extra_objects.append(placeholder)
            object_refs = [placeholder.id]

        stix_report = stix2.Report(
            name=self._report.title,
            description=self._report.summary,
            published=datetime.now(timezone.utc),
            report_types=["threat-report"],
            object_refs=object_refs,
        )

        return stix2.Bundle(objects=[*indicators, *extra_objects, stix_report])

    def filename(self) -> str:
        """出力ファイル名を返す（形式: {title}_{yyyymmdd_hhmmss}.json）。"""
        safe_title = _sanitize_filename(self._report.title)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe_title}_{timestamp}.json"

    def save(self, output_dir: Path) -> Path:
        """指定ディレクトリに STIX Bundle JSON を保存し、保存先 Path を返す。"""
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / self.filename()
        path.write_text(self.build().serialize(pretty=True, ensure_ascii=False), encoding="utf-8")
        return path
