from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import EventType, User, UserRole
from app.schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from app.security import create_access_token, get_password_hash, verify_password
from app.services.audit_service import create_audit_log

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_token_for_credentials(email: str, password: str, db: Session) -> TokenResponse:
    user = db.query(User).filter(User.email == email, User.is_active.is_(True)).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(subject=user.id, role=user.role.value)
    create_audit_log(db, event_type=EventType.login, user_id=user.id, metadata={"email": user.email})
    db.commit()
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    return _issue_token_for_credentials(payload.email, payload.password, db)


@router.post("/token", response_model=TokenResponse)
def token_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Swagger OAuth2 password popup sends username/password as form fields.
    return _issue_token_for_credentials(form_data.username, form_data.password, db)


@router.post("/register", response_model=UserOut)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Public self-registration is user-only; admin accounts remain bootstrap/admin-controlled.
    new_user = User(
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role=UserRole.user,
        is_active=True,
    )
    db.add(new_user)
    create_audit_log(
        db,
        event_type=EventType.admin_action,
        user_id=None,
        metadata={"action": "self_register", "target_email": payload.email, "role": UserRole.user.value},
    )
    db.commit()
    db.refresh(new_user)
    return new_user
