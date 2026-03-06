import mimetypes
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.models import CaseFile, EventType, FileStatus, PiiEntity, User
from app.services.audit_service import create_audit_log
from app.services.crypto_service import crypto_service
from app.services.file_service import (
    IMAGE_TYPES,
    ensure_storage_dirs,
    extract_image_text_with_tokens,
    extract_text,
    save_upload,
    write_sanitized_output,
)
from app.services.image_redaction_service import redact_image_regions
from app.services.masking_service import compute_risk_score, sanitize_text
from app.services.pii_engine import detect_pii
from app.services.supabase_storage import supabase_storage

router = APIRouter(prefix="/upload", tags=["upload"])


def _process_file(
    *,
    db: Session,
    user: User,
    local_path: Path,
    sanitized_path: Path,
    file_type: str,
    masking_mode: str,
    raw_ref: str,
    sanitized_ref: str,
) -> CaseFile:
    case = CaseFile(
        original_path=raw_ref,
        sanitized_path=sanitized_ref,
        file_type=file_type,
        status=FileStatus.scanning,
        uploaded_by=user.id,
    )
    db.add(case)
    db.flush()

    create_audit_log(db, event_type=EventType.upload, user_id=user.id, file_id=case.id, metadata={"path": raw_ref})
    create_audit_log(db, event_type=EventType.scan_start, user_id=user.id, file_id=case.id, metadata={"masking_mode": masking_mode})

    is_image = local_path.suffix.lower() in IMAGE_TYPES
    ocr_tokens = []
    if is_image:
        text, ocr_tokens = extract_image_text_with_tokens(local_path)
    else:
        text = extract_text(local_path)

    detections = detect_pii(text)
    mask_result = sanitize_text(text, detections, masking_mode)

    if is_image:
        redact_image_regions(
            image_path=local_path,
            output_path=sanitized_path,
            detections=detections,
            ocr_tokens=ocr_tokens,
            masking_mode=masking_mode,
        )
    else:
        write_sanitized_output(sanitized_path, mask_result.sanitized_text)

    entities = []
    for det, masked, token_key in mask_result.replacements:
        entities.append(
            PiiEntity(
                file_id=case.id,
                entity_type=det.entity_type,
                original_value=crypto_service.encrypt_text(det.value),
                masked_value=masked,
                token_key=token_key,
                confidence=det.confidence,
                detection_layer=det.layer,
                char_start=det.start,
                char_end=det.end,
            )
        )
    db.add_all(entities)

    plain_original_bytes = local_path.read_bytes()
    encrypted_original_bytes = crypto_service.encrypt_bytes(plain_original_bytes)
    sanitized_bytes = sanitized_path.read_bytes()

    if supabase_storage.enabled:
        original_ct = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
        sanitized_ct = mimetypes.guess_type(sanitized_path.name)[0] or "application/octet-stream"
        supabase_storage.upload_raw(raw_ref, encrypted_original_bytes, original_ct)
        supabase_storage.upload_sanitized(sanitized_ref, sanitized_bytes, sanitized_ct)

        local_path.unlink(missing_ok=True)
        sanitized_path.unlink(missing_ok=True)
    else:
        local_path.write_bytes(encrypted_original_bytes)

    case.pii_count = len(entities)
    case.risk_score = compute_risk_score(detections, len(text))
    case.status = FileStatus.completed

    create_audit_log(
        db,
        event_type=EventType.scan_complete,
        user_id=user.id,
        file_id=case.id,
        metadata={"pii_count": case.pii_count, "risk_score": case.risk_score},
    )
    create_audit_log(
        db,
        event_type=EventType.masked,
        user_id=user.id,
        file_id=case.id,
        metadata={"mode": masking_mode},
    )
    db.commit()
    db.refresh(case)
    return case


@router.post("/single")
async def upload_single(
    file: UploadFile = File(...),
    masking_mode: str = Form("redact"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)
    extension = Path(file.filename).suffix.lower()
    if extension == "":
        raise HTTPException(status_code=400, detail="File extension is required")

    base = Path(file.filename).stem.replace(" ", "_")
    uid = uuid.uuid4().hex[:8]
    raw_name = f"{base}_{uid}{extension}"
    sanitized_name = f"{base}_{uid}_sanitized{extension}"

    raw_path = settings.raw_storage_path / raw_name
    sanitized_path = settings.sanitized_storage_path / sanitized_name

    raw_ref = raw_name if supabase_storage.enabled else str(raw_path)
    sanitized_ref = sanitized_name if supabase_storage.enabled else str(sanitized_path)

    await save_upload(file, raw_path)
    try:
        case = _process_file(
            db=db,
            user=user,
            local_path=raw_path,
            sanitized_path=sanitized_path,
            file_type=extension.lstrip("."),
            masking_mode=masking_mode,
            raw_ref=raw_ref,
            sanitized_ref=sanitized_ref,
        )
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Processing failed: {exc}") from exc

    return {"file_id": case.id, "status": case.status.value, "risk_score": case.risk_score, "pii_count": case.pii_count}


@router.post("/bulk")
async def upload_bulk(
    files: list[UploadFile] = File(...),
    masking_mode: str = Form("redact"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)
    results = []

    for file in files:
        extension = Path(file.filename).suffix.lower()
        if extension == "":
            results.append({"file": file.filename, "status": "failed", "error": "File extension is required"})
            continue

        base = Path(file.filename).stem.replace(" ", "_")
        uid = uuid.uuid4().hex[:8]
        raw_name = f"{base}_{uid}{extension}"
        sanitized_name = f"{base}_{uid}_sanitized{extension}"

        raw_path = settings.raw_storage_path / raw_name
        sanitized_path = settings.sanitized_storage_path / sanitized_name

        raw_ref = raw_name if supabase_storage.enabled else str(raw_path)
        sanitized_ref = sanitized_name if supabase_storage.enabled else str(sanitized_path)

        await save_upload(file, raw_path)
        try:
            case = _process_file(
                db=db,
                user=user,
                local_path=raw_path,
                sanitized_path=sanitized_path,
                file_type=extension.lstrip("."),
                masking_mode=masking_mode,
                raw_ref=raw_ref,
                sanitized_ref=sanitized_ref,
            )
            results.append({"file_id": case.id, "status": case.status.value})
        except Exception as exc:
            db.rollback()
            results.append({"file": file.filename, "status": "failed", "error": str(exc)})

    return {"count": len(results), "results": results}
