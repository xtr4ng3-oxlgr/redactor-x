# Uso

## GUI

```bash
python run_redactorx_gui.py
```

## CLI

```bash
python -m src.redactorx scan ./examples --report reports/scan
python -m src.redactorx redact ./examples --out clean_output --report reports/redacted
```

## Flujo seguro

1. Escanear.
2. Revisar vista previa.
3. Exportar copia limpia.
4. Compartir solo la copia limpia.
