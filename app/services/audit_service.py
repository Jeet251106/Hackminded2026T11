import hashlib
import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import AuditLog, EventType


def _hash_payload(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_audit_log(
    db: Session,
    *,
    event_type: EventType,
    user_id: str | None = None,
    file_id: str | None = None,
    metadata: dict | None = None,
) -> AuditLog:
    metadata = metadata or {}
    prev = db.query(AuditLog).order_by(AuditLog.created_at.desc()).first()
    prev_hash = prev.entry_hash if prev else ""
    ts = datetime.utcnow().isoformat()
    payload = json.dumps(
        {
            "event_type": event_type.value,
            "file_id": file_id,
            "user_id": user_id,
            "metadata": metadata,
            "prev_hash": prev_hash,
            "created_at": ts,
        },
        sort_keys=True,
    )
    entry_hash = _hash_payload(payload)

    log = AuditLog(
        event_type=event_type,
        file_id=file_id,
        user_id=user_id,
        metadata_json=metadata,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(log)
    db.flush()
    return log
