"""Persistent storage backends for White Cell agent brain memory."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class BrainStorageConfig:
    """Configuration for brain memory storage."""

    agent_name: str
    local_dir: Path
    google_drive_enabled: bool = False
    google_drive_folder_id: str | None = None
    google_service_account_file: str | None = None


class BrainStorage:
    """Store and retrieve long-lived helper learning memory."""

    def __init__(self, config: BrainStorageConfig):
        self.config = config
        self.config.local_dir.mkdir(parents=True, exist_ok=True)

    @property
    def local_file(self) -> Path:
        """Local JSON brain file path for current agent."""

        safe_name = self.config.agent_name.replace("/", "_").replace(" ", "_")
        return self.config.local_dir / f"{safe_name}.json"

    def load(self) -> dict[str, Any]:
        """Load brain memory from local file."""

        if not self.local_file.exists():
            return {"helper_learning": []}
        try:
            payload = json.loads(self.local_file.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload.setdefault("helper_learning", [])
                return payload
        except (json.JSONDecodeError, OSError):
            pass
        return {"helper_learning": []}

    def save(self, data: dict[str, Any]) -> None:
        """Save brain memory to local file."""

        self.local_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def sync_to_google_drive(self) -> tuple[bool, str]:
        """Sync the local brain file to Google Drive when configured."""

        if not self.config.google_drive_enabled:
            return False, "Google Drive sync disabled"

        folder_id = self.config.google_drive_folder_id
        sa_file = self.config.google_service_account_file
        if not folder_id or not sa_file:
            return False, "Google Drive config missing folder id or service account file"

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaFileUpload
        except ImportError:
            return False, "Google Drive libraries not installed (google-api-python-client, google-auth)"

        scopes = ["https://www.googleapis.com/auth/drive.file"]
        credentials = service_account.Credentials.from_service_account_file(sa_file, scopes=scopes)
        service = build("drive", "v3", credentials=credentials)

        filename = self.local_file.name
        query = (
            f"name='{filename}' and '{folder_id}' in parents and trashed=false"
        )
        response = service.files().list(q=query, fields="files(id,name)", pageSize=1).execute()
        files = response.get("files", [])

        media = MediaFileUpload(str(self.local_file), mimetype="application/json", resumable=False)
        if files:
            file_id = files[0]["id"]
            service.files().update(fileId=file_id, media_body=media).execute()
            return True, f"Updated Google Drive brain file: {filename}"

        metadata = {"name": filename, "parents": [folder_id]}
        service.files().create(body=metadata, media_body=media, fields="id").execute()
        return True, f"Created Google Drive brain file: {filename}"
