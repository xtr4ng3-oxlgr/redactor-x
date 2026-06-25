from __future__ import annotations

import os
import shutil
import string
from pathlib import Path
from .patterns import SAFE_EXTENSIONS, SKIP_DIR_NAMES


def is_probably_binary(path: Path, sample_size: int = 4096) -> bool:
    try:
        chunk = path.read_bytes()[:sample_size]
    except Exception:
        return True
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    printable = bytes(string.printable, "ascii")
    non_printable = sum(1 for b in chunk if b not in printable and b not in b"\r\n\t")
    return (non_printable / max(len(chunk), 1)) > 0.30


def should_scan_file(path: Path, max_mb: int = 12) -> bool:
    try:
        if path.suffix.lower() not in SAFE_EXTENSIONS:
            return False
        if path.stat().st_size > max_mb * 1024 * 1024:
            return False
        return not is_probably_binary(path)
    except Exception:
        return False


def iter_scan_files(target: Path, max_mb: int = 12):
    target = target.resolve()
    if target.is_file():
        if should_scan_file(target, max_mb=max_mb):
            yield target
        return

    for root, dirs, files in os.walk(target):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
        for name in files:
            path = root_path / name
            if should_scan_file(path, max_mb=max_mb):
                yield path


def read_text_safe(path: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=enc, errors="replace")
        except Exception:
            continue
    return ""


def write_text_safe(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")


def mirror_output_path(source_root: Path, file_path: Path, output_root: Path) -> Path:
    source_root = source_root.resolve()
    file_path = file_path.resolve()
    output_root = output_root.resolve()
    if source_root.is_file():
        return output_root / file_path.name
    try:
        rel = file_path.relative_to(source_root)
    except ValueError:
        rel = Path(file_path.name)
    return output_root / rel


def mask_value(value: str) -> str:
    clean = value.strip()
    if len(clean) <= 8:
        return "<MASKED>"
    return f"{clean[:4]}...{clean[-4:]}"


def make_context(line: str, max_len: int = 180) -> str:
    clean = line.replace("\\t", " ").replace("\\r", " ").replace("\\n", " ")
    if len(clean) > max_len:
        return clean[:max_len] + "..."
    return clean


def copy_non_scanned_tree(source: Path, output: Path, max_mb: int = 12) -> None:
    if source.is_file():
        return
    for root, dirs, files in os.walk(source):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
        for name in files:
            path = root_path / name
            out = mirror_output_path(source, path, output)
            if out.exists():
                continue
            if not should_scan_file(path, max_mb=max_mb):
                try:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, out)
                except Exception:
                    pass
