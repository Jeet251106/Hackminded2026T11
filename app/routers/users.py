from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import EventType, User
from app.schemas import UserOut
from app.services.audit_service import create_audit_log

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    create_audit_log(db, event_type=EventType.admin_action, user_id=admin.id, metadata={"action": "list_users"})
    db.commit()
    return users


@router.delete("/{user_id}")
def deactivate_user(user_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role.value == "admin":
        raise HTTPException(status_code=400, detail="Cannot deactivate admin")

    user.is_active = False
    create_audit_log(
        db,
        event_type=EventType.admin_action,
        user_id=admin.id,
        metadata={"action": "deactivate_user", "target_user_id": user_id},
    )
    db.commit()
    return {"message": "User access revoked"}
