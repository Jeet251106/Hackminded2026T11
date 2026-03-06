from pathlib import Path

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import AuditLog, EventType, User
from app.schemas import AuditLogOut
from app.services.audit_service import create_audit_log
from app.services.report_service import export_audit_pdf

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs", response_model=list[AuditLogOut])
def get_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()
    create_audit_log(db, event_type=EventType.admin_action, user_id=admin.id, metadata={"action": "view_audit_logs"})
    db.commit()
    return logs


@router.get("/export")
def export_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.asc()).all()
    output_path = Path("storage") / "exports" / "chain_of_custody.pdf"
    export_audit_pdf(logs, output_path)

    create_audit_log(db, event_type=EventType.admin_action, user_id=admin.id, metadata={"action": "export_audit_pdf"})
    db.commit()

    return FileResponse(path=output_path, filename="chain_of_custody.pdf", media_type="application/pdf")
