from __future__ import annotations

import base64
import binascii
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import Field

from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.core.errors import Code, MCPError
from ios_decompiler_mcp.core.registry import new_id
from ios_decompiler_mcp.tools.models import ClassName, SessionPage, SessionRequest


class Snapshot(SessionPage):
    root_view_id: str | None = None
    depth: int = Field(default=8, ge=0, le=30)
    max_nodes: int = Field(default=1000, ge=1, le=2000)
    include_text: bool = False


class View(SessionPage):
    view_id: str = Field(min_length=1, max_length=255)
    include_text: bool = False


class HitTest(SessionRequest):
    x: float = Field(allow_inf_nan=False)
    y: float = Field(allow_inf_nan=False)
    window_id: str | None = None
    include_text: bool = False


class FindViews(Snapshot):
    class_name: ClassName | None = None
    text: str | None = Field(default=None, max_length=512)
    accessibility_identifier: str | None = Field(default=None, max_length=255)
    hidden: bool | None = None
    user_interaction_enabled: bool | None = None


class Screenshot(SessionRequest):
    window_id: str | None = None


def register(app: Application) -> None:
    def rpc(method: str) -> Callable[[Any], Awaitable[dict[str, Any]]]:
        async def invoke(request: Any) -> dict[str, Any]:
            app.permissions.device(request.device_id)
            return await app.frida.rpc(request.device_id, request.session_id, method, request.model_dump(exclude={"device_id", "session_id"}))
        return invoke

    async def screenshot(request: Screenshot) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        result = await app.frida.rpc(request.device_id, request.session_id, "screenshot", {"window_id": request.window_id})
        encoded = result.get("base64", "")
        if not isinstance(encoded, str) or len(encoded) > 12 * 1024 * 1024:
            raise MCPError(Code.LIMIT_EXCEEDED, "Screenshot exceeds the encoded size limit")
        try:
            png = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise MCPError(Code.FRIDA_ERROR, "Screenshot agent returned invalid image data") from exc
        if not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png) > 8 * 1024 * 1024:
            raise MCPError(Code.FRIDA_ERROR, "Screenshot is not a bounded PNG")
        directory = app.settings.state_dir / "screenshots"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / (new_id("screenshot") + ".png")
        with path.open("xb") as output:
            path.chmod(0o600)
            output.write(png)
        return {"mime_type": "image/png", "local_path": str(path), "bytes": len(png), "window_id": result.get("window_id"), "observed": True}

    definitions: list[tuple[str, type[SessionRequest], str, str]] = [
        ("ui_get_windows", SessionRequest, "windows", "Enumerate UIWindow/UIScene state on the main thread."),
        ("ui_snapshot", Snapshot, "snapshot", "Return a depth- and size-bounded flat UIKit hierarchy with stable session IDs. Text capture is opt-in."),
        ("ui_inspect_view", View, "inspect_view", "Inspect a retained session-scoped UIView, controller ownership, subviews and target-action mappings."),
        ("ui_get_constraints", View, "constraints", "List this UIView's Auto Layout constraints with pagination."),
        ("ui_get_responder_chain", View, "responders", "Follow observed UIKit responders with a fixed depth cap."),
        ("ui_hit_test", HitTest, "hit_test", "Hit-test UIKit window coordinates in points on the main thread."),
        ("ui_find_views", FindViews, "find_views", "Find views by class, opt-in text, accessibility identifier and allowed properties."),
    ]
    for name, model, operation, description in definitions:
        app.tools.add(name, model, rpc(operation), description)
    app.tools.add("ui_screenshot", Screenshot, screenshot, "Capture an explicitly requested bounded PNG as a local artifact and native MCP image when UIKit rendering is available.")
