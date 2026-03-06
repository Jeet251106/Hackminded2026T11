# CASE FILED Backend (FastAPI)

## Run Local (Default)

```bash
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

## Supabase Integration (Optional)

Set these in `.env` to enable Supabase database/storage:

- `DATABASE_URL=postgresql+psycopg2://...`
- `SUPABASE_URL=https://<project-ref>.supabase.co`
- `SUPABASE_SERVICE_ROLE_KEY=<service-role-key>`
- `SUPABASE_RAW_BUCKET=raw-case-files`
- `SUPABASE_SANITIZED_BUCKET=sanitized-files`

When `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are set:

- Uploaded encrypted originals are stored in Supabase Storage `raw-case-files`
- Sanitized outputs are stored in Supabase Storage `sanitized-files`
- `/files/{id}/download` and `/files/{id}/original` read from Supabase

If those vars are empty, backend uses local `storage/` folders.

## OCR

- Install Tesseract locally, or use Docker/Render image with tesseract installed.
- Optional: set `TESSERACT_CMD` if not in PATH.
