from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import EventType, PiiEntity, User
from app.schemas import DetokenizeRequest, DetokenizeResponse
from app.services.audit_service import create_audit_log
from app.services.crypto_service import crypto_service

router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.post("/detokenize", response_model=DetokenizeResponse)
def detokenize(
    payload: DetokenizeRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    entity = db.query(PiiEntity).filter(PiiEntity.token_key == payload.token_key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Token not found")

    original = crypto_service.decrypt_text(entity.original_value)
    create_audit_log(
        db,
        event_type=EventType.admin_action,
        user_id=admin.id,
        file_id=entity.file_id,
        metadata={"action": "detokenize", "token_key": payload.token_key},
    )
    db.commit()
    return DetokenizeResponse(token_key=payload.token_key, original_value=original)
