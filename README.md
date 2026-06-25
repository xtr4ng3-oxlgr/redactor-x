# REDACTOR-X

**REDACTOR-X** es una herramienta local para detectar, previsualizar y censurar datos sensibles antes de compartir logs, configs, reportes o carpetas de proyecto.

Creado por **xtr4ng3**.

---

## Propósito

Muchas personas comparten archivos sin darse cuenta de que contienen información sensible:

- tokens,
- API keys,
- mails,
- IPs,
- rutas locales,
- nombres de usuario,
- passwords,
- cookies,
- webhooks,
- claves privadas,
- archivos `.env`,
- conexiones a bases de datos,
- logs con datos personales.

**REDACTOR-X** ayuda a revisar y crear una copia limpia antes de subir archivos a GitHub, enviarlos por Discord, compartirlos en soporte técnico o publicarlos en un foro.

No sube archivos.  
No modifica originales.  
No guarda secretos completos en reportes.

---

## Funciones

- GUI oscura y profesional.
- Escaneo de archivos y carpetas.
- Vista previa de hallazgos.
- Exportación de copia censurada.
- CLI para usuarios técnicos.
- Reportes HTML.
- Reportes JSON.
- Motor de patrones.
- Reglas editables.
- Modo seguro: nunca sobrescribe originales.
- Soporte para logs, configs, código y documentación.

---

## Datos que detecta

- Emails.
- IPv4.
- Rutas `C:\Users\...`.
- Rutas `/home/...` y `/Users/...`.
- Discord webhooks.
- GitHub tokens.
- AWS Access Keys.
- Slack tokens.
- JWT.
- Bearer tokens.
- Private keys.
- Password assignments.
- Secret/API key assignments.
- Database URLs.
- Cookie headers.
- Tokens en URLs.

---

## Uso GUI

En Windows:

```bat
run_redactorx.bat
```

O con Python:

```bash
python run_redactorx_gui.py
```

---

## Uso CLI

Escanear:

```bash
python -m src.redactorx scan ./logs --report reports/redactorx_scan
```

Exportar copia censurada:

```bash
python -m src.redactorx redact ./logs --out ./clean_logs --report reports/redactorx_redacted
```

---

## Compilar portable en Windows

```bat
build_windows\1_COMPILAR_EXE_PORTABLE.bat
```

---

## Seguridad

REDACTOR-X no borra archivos, no envía datos a internet, no cambia originales y no guarda secretos completos en reportes.

---

## Licencia

MIT.

**xtr4ng3**
