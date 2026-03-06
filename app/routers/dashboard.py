from sqlalchemy import func
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import AuditLog, CaseFile, User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    total_cases = db.query(func.count(CaseFile.id)).scalar() or 0
    total_entities = db.query(func.coalesce(func.sum(CaseFile.pii_count), 0)).scalar() or 0
    avg_risk = db.query(func.coalesce(func.avg(CaseFile.risk_score), 0)).scalar() or 0

    risk_bands = {
        "low": db.query(func.count(CaseFile.id)).filter(CaseFile.risk_score.between(0, 20)).scalar() or 0,
        "moderate": db.query(func.count(CaseFile.id)).filter(CaseFile.risk_score.between(21, 50)).scalar() or 0,
        "high": db.query(func.count(CaseFile.id)).filter(CaseFile.risk_score.between(51, 80)).scalar() or 0,
        "critical": db.query(func.count(CaseFile.id)).filter(CaseFile.risk_score.between(81, 100)).scalar() or 0,
    }

    recent_activity = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(20).all()

    return {
        "total_cases": total_cases,
        "total_entities": int(total_entities),
        "average_risk": round(float(avg_risk), 2),
        "risk_distribution": risk_bands,
        "recent_activity": [
            {
                "event_type": item.event_type.value,
                "file_id": item.file_id,
                "user_id": item.user_id,
                "created_at": item.created_at.isoformat(),
            }
            for item in recent_activity
        ],
    }
