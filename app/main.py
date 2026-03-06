from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import settings
from app.database import Base, SessionLocal, engine
from app.routers import audit, auth, dashboard, files, scan, tokens, upload, users
from app.services.bootstrap import ensure_admin_user
from app.services.file_service import ensure_storage_dirs


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)

    db = SessionLocal()
    try:
        ensure_admin_user(db, settings.initial_admin_email, settings.initial_admin_password)
    finally:
        db.close()

    yield


app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=lifespan)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(upload.router)
app.include_router(files.router)
app.include_router(scan.router)
app.include_router(tokens.router)
app.include_router(audit.router)
app.include_router(dashboard.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}
