import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"


class FileStatus(str, enum.Enum):
    pending = "pending"
    scanning = "scanning"
    completed = "completed"
    failed = "failed"


class EventType(str, enum.Enum):
    upload = "upload"
    scan_start = "scan_start"
    scan_complete = "scan_complete"
    pii_found = "pii_found"
    masked = "masked"
    download = "download"
    login = "login"
    logout = "logout"
    admin_action = "admin_action"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.user, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class CaseFile(Base):
    __tablename__ = "case_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sanitized_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[FileStatus] = mapped_column(Enum(FileStatus), default=FileStatus.pending, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pii_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    entities: Mapped[list["PiiEntity"]] = relationship(back_populates="case_file", cascade="all, delete-orphan")


class PiiEntity(Base):
    __tablename__ = "pii_entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("case_files.id"), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    original_value: Mapped[str] = mapped_column(Text, nullable=False)
    masked_value: Mapped[str] = mapped_column(Text, nullable=False)
    token_key: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    detection_layer: Mapped[str] = mapped_column(String(30), nullable=False)
    char_start: Mapped[int] = mapped_column(Integer, nullable=False)
    char_end: Mapped[int] = mapped_column(Integer, nullable=False)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    case_file: Mapped[CaseFile] = relationship(back_populates="entities")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type: Mapped[EventType] = mapped_column(Enum(EventType), nullable=False)
    file_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("case_files.id"), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
