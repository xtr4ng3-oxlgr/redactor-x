from __future__ import annotations
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    file_path: str
    line: int
    column: int
    pattern: str
    label: str
    severity: str
    masked_value: str
    context: str
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ScanSummary:
    target: str
    files_scanned: int
    files_skipped: int
    findings: int
    critical: int
    high: int
    medium: int
    low: int
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class RedactionResult:
    source: str
    output: str
    files_written: int
    files_skipped: int
    replacements: int
    def to_dict(self) -> dict:
        return asdict(self)
