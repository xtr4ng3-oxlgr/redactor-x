from __future__ import annotations

from pathlib import Path
from typing import Iterable
from .models import Finding, ScanSummary
from .patterns import DEFAULT_PATTERNS, RedactionPattern
from .utils import iter_scan_files, mask_value, make_context, read_text_safe


class RedactorEngine:
    def __init__(self, patterns: Iterable[RedactionPattern] | None = None):
        self.patterns = list(patterns or DEFAULT_PATTERNS)

    def scan_text(self, text: str, file_path: str = "<memory>") -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in self.patterns:
                for match in pattern.regex.finditer(line):
                    findings.append(Finding(
                        file_path=file_path,
                        line=line_no,
                        column=match.start() + 1,
                        pattern=pattern.name,
                        label=pattern.label,
                        severity=pattern.severity,
                        masked_value=mask_value(match.group(0)),
                        context=make_context(line),
                    ))
        return findings

    def scan_path(self, target: Path, max_mb: int = 12) -> tuple[ScanSummary, list[Finding]]:
        target = Path(target)
        findings: list[Finding] = []
        files_skipped = 0
        candidates = list(iter_scan_files(target, max_mb=max_mb))

        for file_path in candidates:
            text = read_text_safe(file_path)
            if not text:
                files_skipped += 1
                continue
            findings.extend(self.scan_text(text, str(file_path)))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1

        return ScanSummary(
            target=str(target),
            files_scanned=len(candidates),
            files_skipped=files_skipped,
            findings=len(findings),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
        ), findings

    def redact_text(self, text: str) -> tuple[str, int]:
        output = text
        replacements = 0
        # xtr4ng3: mask first, report later.
        for pattern in self.patterns:
            output, count = pattern.regex.subn(pattern.replacement, output)
            replacements += count
        return output, replacements
