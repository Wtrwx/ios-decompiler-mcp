from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from ios_decompiler_mcp.config import Settings
from ios_decompiler_mcp.core.errors import Code, MCPError
from ios_decompiler_mcp.core.registry import Registry, new_id


def canonical_scope(scope: dict[str, Any]) -> str:
    return json.dumps(scope, sort_keys=True, separators=(",", ":"))


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Permissions:
    def __init__(self, settings: Settings, registry: Registry):
        self.settings = settings
        self.registry = registry

    def device(self, device_id: str, bundle_id: str | None = None) -> None:
        device = self.settings.devices.get(device_id)
        if device is None:
            raise MCPError(Code.NOT_ALLOWED, "Device is not configured in the allowlist", device_id=device_id)
        if bundle_id is not None and bundle_id not in device.allowed_apps:
            raise MCPError(Code.NOT_ALLOWED, "Application is not in this device's allowlist", device_id=device_id, bundle_id=bundle_id)

    def local_path(self, path: Path, *, must_exist: bool = False) -> Path:
        resolved = path.expanduser().resolve()
        if not any(resolved.is_relative_to(root) for root in (self.settings.workspace, self.settings.state_dir)):
            raise MCPError(Code.NOT_ALLOWED, "Local path is outside configured workspace/state directory")
        if must_exist and not resolved.is_file():
            raise MCPError(Code.NOT_FOUND, "Local file does not exist", path=str(resolved))
        return resolved

    def download_path(self, path: Path) -> Path:
        resolved = path.expanduser().resolve()
        if not resolved.is_relative_to(self.settings.state_dir / "downloads") or resolved.exists():
            raise MCPError(Code.NOT_ALLOWED, "Downloads require a new file under the server state's downloads directory")
        return resolved

    def request(self, action: str, scope: dict[str, Any]) -> dict[str, Any]:
        encoded = canonical_scope(scope)
        existing = self.registry.db.execute("SELECT id,expires FROM approvals WHERE action=? AND scope=? AND status='pending' AND expires>?", (action, encoded, time.time())).fetchone()
        if existing:
            request_id, expires = existing
        else:
            request_id, expires = new_id("approval"), time.time() + 600
            self.registry.db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?)", (request_id, action, encoded, "pending", expires, time.time()))
            self.registry.db.commit()
        return {"approval_id": request_id, "action": action, "scope": scope, "expires_at": expires, "operator_command": f"ios-decompiler-mcp-approve --state-dir <server-state-dir> {request_id}"}

    def require(self, action: str, scope: dict[str, Any], approval_id: str | None) -> None:
        if not approval_id:
            raise MCPError(Code.APPROVAL_REQUIRED, "A local operator must approve this exact operation", **self.request(action, scope))
        now = time.time()
        # Single transaction makes approvals one-use even when concurrent clients retry.
        cursor = self.registry.db.execute("UPDATE approvals SET status='consumed' WHERE id=? AND action=? AND scope=? AND status='granted' AND expires>?", (approval_id, action, canonical_scope(scope), now))
        self.registry.db.commit()
        if cursor.rowcount != 1:
            raise MCPError(Code.APPROVAL_INVALID, "Approval is expired, consumed, not granted, or bound to different arguments")
        self.registry.audit(approval_id, action, "approval_consumed", scope)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local operator approval; never exposed as an MCP tool")
    parser.add_argument("approval_id")
    parser.add_argument("--state-dir", type=Path, default=Settings().state_dir)
    args = parser.parse_args()
    registry = Registry(args.state_dir.expanduser().resolve())
    try:
        row = registry.db.execute("SELECT action,scope,status,expires FROM approvals WHERE id=?", (args.approval_id,)).fetchone()
        if not row or row[2] != "pending" or row[3] <= time.time():
            parser.error("approval is missing, expired, or no longer pending")
        print(json.dumps({"action": row[0], "scope": json.loads(row[1])}, indent=2))
        if input("Type approve to grant this one operation for ten minutes: ").strip() != "approve":
            raise SystemExit("Not approved")
        registry.db.execute("UPDATE approvals SET status='granted',expires=? WHERE id=? AND status='pending'", (time.time() + 600, args.approval_id))
        registry.db.commit()
        registry.audit(args.approval_id, row[0], "operator_granted")
        print("Approved:", args.approval_id)
    finally:
        registry.close()


if __name__ == "__main__":
    main()
