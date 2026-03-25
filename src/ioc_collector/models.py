"""データモデル定義。"""

from enum import Enum

from pydantic import BaseModel, Field


class IoCType(str, Enum):
    """IoC の種別。STIX 2.1 の SCO (Cyber Observable) に対応。"""

    IPV4_ADDR = "ipv4-addr"
    DOMAIN_NAME = "domain-name"
    URL = "url"
    FILE_HASH_MD5 = "file-hash-md5"
    FILE_HASH_SHA1 = "file-hash-sha1"
    FILE_HASH_SHA256 = "file-hash-sha256"
    FILE_NAME = "file-name"
    PROCESS_NAME = "process-name"
    OTHER = "other"


class IoCEntry(BaseModel):
    """個々の IoC エントリ。"""

    type: IoCType = Field(description="IoC の種別")
    value: str = Field(description="IoC の値（例: IPアドレス, ドメイン, ハッシュ値等）")
    description: str = Field(default="", description="補足説明（例: C2 server, dropper hash）")


class ReferenceEntry(BaseModel):
    """参考情報のエントリ（タイトルと URL の組）。"""

    title: str = Field(description="参考ページのタイトルまたは説明")
    url: str = Field(description="参考ページの完全な URL（例: https://example.com/report）")


class IncidentReport(BaseModel):
    """セキュリティインシデントの構造化レポート。"""

    title: str = Field(description="インシデント名（ファイル名にも使用）")
    summary: str = Field(description="インシデントの概要")
    timeline: list[str] = Field(
        default_factory=list,
        description="タイムライン（例: '2024-01-10: Initial access via phishing'）",
    )
    affected_scope: str = Field(description="影響を受けたシステム・組織・範囲")
    countermeasures: list[str] = Field(
        default_factory=list,
        description="推奨される対策・緩和策",
    )
    iocs: list[IoCEntry] = Field(
        default_factory=list,
        description="IoC 一覧（型付き）",
    )
    references: list[ReferenceEntry] = Field(
        default_factory=list,
        description="参考情報のタイトルと URL の一覧",
    )
