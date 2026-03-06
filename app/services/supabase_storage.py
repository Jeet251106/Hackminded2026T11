from supabase import Client, create_client

from app.core.config import settings


class SupabaseStorageService:
    def __init__(self) -> None:
        self.enabled = settings.use_supabase_storage
        self.client: Client | None = None
        if self.enabled:
            self.client = create_client(settings.supabase_url, settings.supabase_service_role_key)

    def _require_client(self) -> Client:
        if not self.client:
            raise RuntimeError("Supabase storage is not configured")
        return self.client

    def upload_raw(self, path: str, content: bytes, content_type: str = "application/octet-stream") -> None:
        client = self._require_client()
        client.storage.from_(settings.supabase_raw_bucket).upload(
            path=path,
            file=content,
            file_options={"content-type": content_type, "upsert": "true"},
        )

    def upload_sanitized(self, path: str, content: bytes, content_type: str = "application/octet-stream") -> None:
        client = self._require_client()
        client.storage.from_(settings.supabase_sanitized_bucket).upload(
            path=path,
            file=content,
            file_options={"content-type": content_type, "upsert": "true"},
        )

    def download_raw(self, path: str) -> bytes:
        client = self._require_client()
        return client.storage.from_(settings.supabase_raw_bucket).download(path)

    def download_sanitized(self, path: str) -> bytes:
        client = self._require_client()
        return client.storage.from_(settings.supabase_sanitized_bucket).download(path)


supabase_storage = SupabaseStorageService()
