import mimetypes
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_user
from app.models import CaseFile, EventType, PiiEntity, User, UserRole
from app.schemas import CaseFileOut, CaseResultOut, PiiEntityOut
from app.services.audit_service import create_audit_log
from app.services.crypto_service import crypto_service
from app.services.supabase_storage import supabase_storage

router = APIRouter(prefix="/files", tags=["files"])


def _assert_case_access(case: CaseFile, user: User) -> None:
    if user.role == UserRole.admin:
        return
    if case.uploaded_by != user.id:
        raise HTTPException(status_code=403, detail="Not authorized for this file")


@router.get("/", response_model=list[CaseFileOut])
def list_files(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    query = db.query(CaseFile).order_by(CaseFile.created_at.desc())
    if user.role != UserRole.admin:
        query = query.filter(CaseFile.uploaded_by == user.id).filter(CaseFile.sanitized_path.is_not(None))
    return query.all()


@router.get("/{file_id}/result", response_model=CaseResultOut)
def file_result(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")
    _assert_case_access(case, user)

    entities = db.query(PiiEntity).filter(PiiEntity.file_id == file_id, PiiEntity.is_false_positive.is_(False)).all()
    if user.role != UserRole.admin:
        masked_entities = [
            PiiEntityOut(
                id=e.id,
                entity_type=e.entity_type,
                masked_value=e.masked_value,
                token_key=None,
                confidence=e.confidence,
                detection_layer=e.detection_layer,
                char_start=e.char_start,
                char_end=e.char_end,
            )
            for e in entities
        ]
        return CaseResultOut(file=case, entities=masked_entities)

    return CaseResultOut(file=case, entities=entities)


@router.get("/{file_id}/download")
def download_sanitized(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")
    _assert_case_access(case, user)

    create_audit_log(db, event_type=EventType.download, user_id=user.id, file_id=file_id, metadata={"target": "sanitized"})
    db.commit()

    if supabase_storage.enabled:
        try:
            data = supabase_storage.download_sanitized(case.sanitized_path)
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Sanitized file not found in storage") from exc

        filename = Path(case.sanitized_path).name
        media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return StreamingResponse(
            iter([data]),
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    path = Path(case.sanitized_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Sanitized file not found")
    return FileResponse(path=path, filename=path.name)


@router.get("/{file_id}/original")
def download_original(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")

    if supabase_storage.enabled:
        try:
            encrypted_data = supabase_storage.download_raw(case.original_path)
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Original file not found in storage") from exc
    else:
        path = Path(case.original_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Original file not found")
        encrypted_data = path.read_bytes()

    try:
        data = crypto_service.decrypt_bytes(encrypted_data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to decrypt original file") from exc

    create_audit_log(db, event_type=EventType.download, user_id=user.id, file_id=file_id, metadata={"target": "original"})
    db.commit()

    original_name = Path(case.original_path).name
    return StreamingResponse(
        iter([data]),
        media_type=mimetypes.guess_type(original_name)[0] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{original_name}"'},
    )
