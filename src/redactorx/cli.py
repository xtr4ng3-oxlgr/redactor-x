from __future__ import annotations
import argparse
from pathlib import Path
from . import APP_NAME, APP_VERSION
from .engine import RedactorEngine
from .redaction import redact_path
from .reports import write_html_report, write_json_report


def main() -> int:
    parser = argparse.ArgumentParser(prog="redactorx", description="Local sensitive-data redaction toolkit.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="scan file or folder")
    scan_p.add_argument("target")
    scan_p.add_argument("--report", default=None)

    redact_p = sub.add_parser("redact", help="export redacted copy")
    redact_p.add_argument("target")
    redact_p.add_argument("--out", required=True)
    redact_p.add_argument("--copy-other-files", action="store_true")
    redact_p.add_argument("--report", default=None)

    args = parser.parse_args()
    engine = RedactorEngine()

    if args.cmd == "scan":
        summary, findings = engine.scan_path(Path(args.target))
        print(f"{APP_NAME} v{APP_VERSION}")
        print(f"target: {summary.target}")
        print(f"files scanned: {summary.files_scanned}")
        print(f"findings: {summary.findings}")
        print(f"critical={summary.critical} high={summary.high} medium={summary.medium} low={summary.low}")
        if args.report:
            out = Path(args.report)
            write_json_report(out.with_suffix(".json"), summary, findings)
            write_html_report(out.with_suffix(".html"), summary, findings)
        return 0

    if args.cmd == "redact":
        summary, findings = engine.scan_path(Path(args.target))
        result = redact_path(Path(args.target), Path(args.out), engine=engine, copy_other_files=args.copy_other_files)
        print(f"redacted files: {result.files_written}")
        print(f"replacements: {result.replacements}")
        if args.report:
            out = Path(args.report)
            write_json_report(out.with_suffix(".json"), summary, findings, result)
            write_html_report(out.with_suffix(".html"), summary, findings, result)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
