from __future__ import annotations
import datetime as dt
import html
import json
from pathlib import Path
from . import APP_NAME, APP_VERSION, AUTHOR
from .models import Finding, RedactionResult, ScanSummary


def write_json_report(path: Path, summary: ScanSummary, findings: list[Finding], redaction: RedactionResult | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "author": AUTHOR,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "summary": summary.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "redaction": redaction.to_dict() if redaction else None,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_html_report(path: Path, summary: ScanSummary, findings: list[Finding], redaction: RedactionResult | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for f in findings[:1000]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(f.severity)}</td>"
            f"<td>{html.escape(f.label)}</td>"
            f"<td><code>{html.escape(f.file_path)}</code></td>"
            f"<td>{f.line}:{f.column}</td>"
            f"<td><code>{html.escape(f.masked_value)}</code></td>"
            f"<td>{html.escape(f.context)}</td>"
            "</tr>"
        )

    redaction_block = ""
    if redaction:
        redaction_block = f"""
        <div class="card">
          <h2>Exportación limpia</h2>
          <table>
            <tr><th>Salida</th><td><code>{html.escape(redaction.output)}</code></td></tr>
            <tr><th>Archivos escritos</th><td>{redaction.files_written}</td></tr>
            <tr><th>Reemplazos</th><td>{redaction.replacements}</td></tr>
          </table>
        </div>
        """

    doc = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>REDACTOR-X Report</title>
<style>
body{{background:#05070b;color:#e8f6ff;font-family:Consolas,Segoe UI,Arial;padding:30px}}
h1,h2{{color:#ff304f}}
.card{{background:#0b1018;border:1px solid #202c3f;border-radius:16px;padding:18px;margin:18px 0;box-shadow:0 0 24px rgba(255,48,79,.08)}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
td,th{{border-bottom:1px solid #1a2130;padding:9px;text-align:left;vertical-align:top}}
th{{color:#7ef9ff}}
code{{color:#d6f7ff}}
.score{{font-size:46px;font-weight:900;color:#ff304f}}
.small{{color:#9fb1c7}}
</style>
</head>
<body>
<h1>REDACTOR-X</h1>
<p class="small">Local Sensitive Data Redaction Toolkit · xtr4ng3 · {dt.datetime.now().isoformat(timespec="seconds")}</p>
<div class="card">
<h2>Resumen</h2>
<div class="score">{summary.findings} hallazgos</div>
<table>
<tr><th>Objetivo</th><td><code>{html.escape(summary.target)}</code></td></tr>
<tr><th>Archivos escaneados</th><td>{summary.files_scanned}</td></tr>
<tr><th>Críticos</th><td>{summary.critical}</td></tr>
<tr><th>Altos</th><td>{summary.high}</td></tr>
<tr><th>Medios</th><td>{summary.medium}</td></tr>
<tr><th>Bajos</th><td>{summary.low}</td></tr>
</table>
</div>
{redaction_block}
<div class="card">
<h2>Hallazgos</h2>
<table>
<tr><th>Severidad</th><th>Tipo</th><th>Archivo</th><th>Línea</th><th>Valor</th><th>Contexto</th></tr>
{''.join(rows)}
</table>
</div>
<p class="small">REDACTOR-X no sube archivos, no modifica originales y no guarda secretos completos en reportes.</p>
</body>
</html>"""
    path.write_text(doc, encoding="utf-8")
