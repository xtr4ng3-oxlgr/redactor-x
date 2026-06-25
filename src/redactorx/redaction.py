from __future__ import annotations
from pathlib import Path
from .engine import RedactorEngine
from .models import RedactionResult
from .utils import copy_non_scanned_tree, iter_scan_files, mirror_output_path, read_text_safe, write_text_safe


def redact_path(source: Path, output_dir: Path, engine: RedactorEngine | None = None, max_mb: int = 12, copy_other_files: bool = False) -> RedactionResult:
    source = Path(source)
    output_dir = Path(output_dir)
    engine = engine or RedactorEngine()

    files_written = 0
    files_skipped = 0
    replacements = 0

    # xtr4ng3: never overwrite original files.
    for file_path in iter_scan_files(source, max_mb=max_mb):
        try:
            text = read_text_safe(file_path)
            redacted, count = engine.redact_text(text)
            out = mirror_output_path(source, file_path, output_dir)
            write_text_safe(out, redacted)
            files_written += 1
            replacements += count
        except Exception:
            files_skipped += 1

    if copy_other_files:
        copy_non_scanned_tree(source, output_dir, max_mb=max_mb)

    return RedactionResult(str(source), str(output_dir), files_written, files_skipped, replacements)
