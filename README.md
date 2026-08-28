# SQL perdidos · Streamlit

Usa un Google Sheet público; no requiere Google Cloud ni service account.

## Secrets
```toml
[google_sheets]
spreadsheet_id = "ID_DEL_ARCHIVO"
leads_gid = "GID_LEADS"
sales_gid = "GID_PROCESO_VENTA"
notes_gid = "GID_NOTAS"
conversations_gid = "GID_CONVERSACIONES"
```

El único identificador de lead visible en la UI es `deal_id`. Nombres, correos, teléfonos, URLs y valores sensibles conocidos se redactan en notas/conversaciones.

## GitHub
```bash
git init
git add .
git commit -m "Initial SQL lost deals dashboard"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
git push -u origin main
```

## Local
```bash
pip install -r requirements.txt
streamlit run app.py
```
