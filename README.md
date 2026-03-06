# THE BUREAU Backend

## Run

```bash
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

## V2 Additions Implemented

- Contextual PII linking (window + field-name anchors)
- Security sweep gate (VirusTotal hash lookup)
- Public operative self-registration
- Row-level case privacy (`owner_id` enforcement)
- Batch uploads (`/upload/batch`) and status (`/upload/batch/{id}/status`)
- Auto-detect zip archives in `/upload/bulk`
- Duplicate detection via SHA-256
- Honeypot validation (`bureau_field`)
- File size anomaly and magic-byte checks
- EXIF stripping for images before processing
- Biometric recognizer expansion
- Format-preserving sealed output extension
- Bulk sealed download zip (`/files/bulk-download`)
- Auto-destruct scheduler every 30 min

## Important Notes

- If `VIRUSTOTAL_API_KEY` is empty, security sweep defaults to optimistic pass.
- For existing local DBs, reset/migrate schema because `case_files` and enums were expanded.
- For OCR in cloud, use Docker with Tesseract installed.
