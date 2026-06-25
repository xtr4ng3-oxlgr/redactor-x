from __future__ import annotations

import datetime as dt
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, APP_VERSION, AUTHOR, INTERNAL_MARK
from .engine import RedactorEngine
from .models import Finding, RedactionResult, ScanSummary
from .redaction import redact_path
from .reports import write_html_report, write_json_report


class RedactorXGui:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} // {AUTHOR}")
        self.root.geometry("1380x900")
        self.root.minsize(1180, 760)
        self.root.configure(bg="#05070b")

        self.engine = RedactorEngine()
        self.target: Path | None = None
        self.output: Path | None = None
        self.summary: ScanSummary | None = None
        self.findings: list[Finding] = []
        self.redaction: RedactionResult | None = None

        self.setup_style()
        self.build_ui()

    def setup_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background="#05070b", foreground="#e8f6ff", fieldbackground="#0b1018")
        style.configure("TFrame", background="#05070b")
        style.configure("Panel.TFrame", background="#0b1018")
        style.configure("TLabel", background="#05070b", foreground="#e8f6ff")
        style.configure("Panel.TLabel", background="#0b1018", foreground="#e8f6ff")
        style.configure("Header.TLabel", background="#05070b", foreground="#ff304f", font=("Segoe UI", 22, "bold"))
        style.configure("Sub.TLabel", background="#05070b", foreground="#9fb1c7", font=("Segoe UI", 9))
        style.configure("Card.TLabel", background="#0b1018", foreground="#ffffff", font=("Segoe UI", 28, "bold"))
        style.configure("TButton", background="#121927", foreground="#e8f6ff", padding=8)
        style.configure("Accent.TButton", background="#5b0f1a", foreground="#ffffff", padding=9)
        style.map("Accent.TButton", background=[("active", "#8a1328")])
        style.configure("Treeview", background="#090d14", foreground="#e8f6ff", fieldbackground="#090d14", rowheight=27)
        style.configure("Treeview.Heading", background="#11192a", foreground="#7ef9ff")

    def build_ui(self) -> None:
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=14, pady=(10, 6))

        title_row = ttk.Frame(top)
        title_row.pack(fill=tk.X)
        ttk.Label(title_row, text="REDACTOR-X", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(title_row, text="  Local Sensitive Data Redaction Toolkit", style="Sub.TLabel").pack(side=tk.LEFT, padx=10)

        banner = tk.Text(top, height=5, bg="#06080d", fg="#ff304f", relief="flat", font=("Consolas", 10, "bold"))
        banner.pack(fill=tk.X, pady=(10, 4))
        banner.insert("1.0", self.ascii_banner())
        banner.config(state="disabled")

        buttons = ttk.Frame(self.root)
        buttons.pack(fill=tk.X, padx=14, pady=(2, 8))
        ttk.Button(buttons, text="Seleccionar archivo/carpeta", style="Accent.TButton", command=self.choose_target).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Escanear", command=self.scan).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Elegir salida limpia", command=self.choose_output).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Exportar copia censurada", command=self.export_redacted).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Generar reportes", command=self.generate_reports).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Ayuda", command=self.show_help).pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="Listo. Selecciona un archivo o carpeta para comenzar.")
        ttk.Label(self.root, textvariable=self.status_var, style="Sub.TLabel").pack(anchor="w", padx=18)

        self.build_cards()

        body = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=10)

        left = ttk.Frame(body)
        right = ttk.Frame(body)
        body.add(left, weight=3)
        body.add(right, weight=2)

        ttk.Label(left, text="Hallazgos", style="Sub.TLabel").pack(anchor="w", pady=(0, 4))
        self.tree = ttk.Treeview(left, columns=("sev", "type", "file", "line", "value"), show="headings")
        for col, title, width in [
            ("sev", "Severidad", 100), ("type", "Tipo", 190), ("file", "Archivo", 520),
            ("line", "Línea", 80), ("value", "Valor", 160),
        ]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_finding)

        ttk.Label(right, text="Vista previa / contexto", style="Sub.TLabel").pack(anchor="w", pady=(0, 4))
        self.preview = tk.Text(right, bg="#06080d", fg="#e8f6ff", insertbackground="#ffffff", relief="flat", wrap="word", font=("Consolas", 10))
        self.preview.pack(fill=tk.BOTH, expand=True)

        bottom = ttk.Frame(self.root)
        bottom.pack(fill=tk.X, padx=14, pady=(0, 10))
        self.log_box = tk.Text(bottom, height=4, bg="#06080d", fg="#d6f7ff", relief="flat", font=("Consolas", 9))
        self.log_box.pack(fill=tk.X)

    def build_cards(self) -> None:
        row = ttk.Frame(self.root)
        row.pack(fill=tk.X, padx=14, pady=8)
        self.card_vars = {
            "files": tk.StringVar(value="0"), "findings": tk.StringVar(value="0"),
            "critical": tk.StringVar(value="0"), "high": tk.StringVar(value="0"),
            "output": tk.StringVar(value="NO"),
        }
        for title, key in [("ARCHIVOS", "files"), ("HALLAZGOS", "findings"), ("CRÍTICOS", "critical"), ("ALTOS", "high"), ("SALIDA", "output")]:
            card = ttk.Frame(row, style="Panel.TFrame")
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            ttk.Label(card, text=title, style="Panel.TLabel").pack(anchor="w", padx=12, pady=(8, 0))
            ttk.Label(card, textvariable=self.card_vars[key], style="Card.TLabel").pack(anchor="w", padx=12, pady=(0, 10))

    def ascii_banner(self) -> str:
        return """
██████╗ ███████╗██████╗  █████╗  ██████╗████████╗ ██████╗ ██████╗       ██╗  ██╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗      ╚██╗██╔╝
██████╔╝█████╗  ██║  ██║███████║██║        ██║   ██║   ██║██████╔╝█████╗╚███╔╝ 
██╔══██╗██╔══╝  ██║  ██║██╔══██║██║        ██║   ██║   ██║██╔══██╗╚════╝██╔██╗ 
██║  ██║███████╗██████╔╝██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║     ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝     ╚═╝  ╚═╝
        """.strip()

    def log(self, text: str) -> None:
        self.log_box.insert(tk.END, f"[{dt.datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.log_box.see(tk.END)

    def choose_target(self) -> None:
        path = filedialog.askdirectory(title="Seleccionar carpeta")
        if not path:
            file = filedialog.askopenfilename(title="Seleccionar archivo")
            if not file:
                return
            path = file
        self.target = Path(path)
        self.status_var.set(f"Objetivo: {self.target}")
        self.log(f"Objetivo seleccionado: {self.target}")

    def choose_output(self) -> None:
        path = filedialog.askdirectory(title="Seleccionar carpeta de salida")
        if not path:
            return
        self.output = Path(path)
        self.card_vars["output"].set("OK")
        self.log(f"Salida seleccionada: {self.output}")

    def scan(self) -> None:
        if not self.target:
            messagebox.showwarning(APP_NAME, "Primero selecciona un archivo o carpeta.")
            return
        self.status_var.set("Escaneando...")
        self.log("Escaneo iniciado.")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        summary, findings = self.engine.scan_path(self.target)
        self.root.after(0, lambda: self.apply_scan(summary, findings))

    def apply_scan(self, summary: ScanSummary, findings: list[Finding]) -> None:
        self.summary = summary
        self.findings = findings
        self.card_vars["files"].set(str(summary.files_scanned))
        self.card_vars["findings"].set(str(summary.findings))
        self.card_vars["critical"].set(str(summary.critical))
        self.card_vars["high"].set(str(summary.high))
        self.tree.delete(*self.tree.get_children())
        for idx, f in enumerate(findings):
            self.tree.insert("", tk.END, iid=str(idx), values=(f.severity, f.label, f.file_path, f"{f.line}:{f.column}", f.masked_value))
        self.status_var.set(f"Escaneo completo: {summary.findings} hallazgos en {summary.files_scanned} archivos.")
        self.log(f"Escaneo completo. Hallazgos: {summary.findings}")

    def on_select_finding(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx >= len(self.findings):
            return
        f = self.findings[idx]
        self.preview.delete("1.0", tk.END)
        self.preview.insert(tk.END, f"Archivo: {f.file_path}\nLínea: {f.line}, columna: {f.column}\nTipo: {f.label}\nSeveridad: {f.severity}\nValor: {f.masked_value}\n\nContexto:\n{f.context}\n")

    def export_redacted(self) -> None:
        if not self.target:
            messagebox.showwarning(APP_NAME, "Primero selecciona un objetivo.")
            return
        if not self.output:
            messagebox.showwarning(APP_NAME, "Primero selecciona una carpeta de salida.")
            return
        self.log("Exportación limpia iniciada.")
        threading.Thread(target=self._export_worker, daemon=True).start()

    def _export_worker(self) -> None:
        result = redact_path(self.target, self.output, engine=self.engine, copy_other_files=False)
        self.root.after(0, lambda: self.apply_export(result))

    def apply_export(self, result: RedactionResult) -> None:
        self.redaction = result
        self.status_var.set(f"Copia censurada exportada: {result.files_written} archivos, {result.replacements} reemplazos.")
        self.log(f"Exportación lista. Archivos: {result.files_written}. Reemplazos: {result.replacements}")

    def generate_reports(self) -> None:
        if not self.summary:
            messagebox.showwarning(APP_NAME, "Primero ejecuta un escaneo.")
            return
        reports_dir = Path.cwd() / "reports"
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = reports_dir / f"redactorx_{stamp}.html"
        json_path = reports_dir / f"redactorx_{stamp}.json"
        write_html_report(html_path, self.summary, self.findings, self.redaction)
        write_json_report(json_path, self.summary, self.findings, self.redaction)
        self.log(f"Reportes generados: {html_path}")
        messagebox.showinfo(APP_NAME, f"Reportes generados:\n{html_path}\n{json_path}")

    def show_help(self) -> None:
        messagebox.showinfo(
            APP_NAME,
            "REDACTOR-X censura datos sensibles antes de compartir logs, configs o reportes.\\n\\n"
            "Flujo recomendado:\\n1. Selecciona archivo o carpeta.\\n2. Escanea.\\n3. Revisa hallazgos.\\n4. Selecciona carpeta de salida.\\n5. Exporta copia censurada.\\n\\n"
            f"No modifica originales. No sube archivos. Marca interna: {INTERNAL_MARK}",
        )

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    RedactorXGui().run()


if __name__ == "__main__":
    main()
