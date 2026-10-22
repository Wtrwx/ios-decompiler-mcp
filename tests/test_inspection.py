from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.core.errors import MCPError
from ios_decompiler_mcp.core.objc_types import decode_encoding, header, signature
from ios_decompiler_mcp.core.sessions import ProcessSession


def test_signature_generation_rejects_ambiguous_abi():
    declaration, certain = signature("viewDidAppear:", "v20@0:8B16")
    assert declaration == "- (void)viewDidAppear:(BOOL)arg0" and certain
    assert signature("buttonTapped:", "v24@0:8@16")[0].endswith("buttonTapped:(id)arg0")
    with pytest.raises(MCPError):
        signature("takesTwo:and:", "v24@0:8@16")
    assert not signature("unknown", "?16@0:8")[1]
    assert len(decode_encoding("{CGRect={CGPoint=dd}{CGSize=dd}}16@0:8")) == 3
    assert decode_encoding("^v")[0].spelling == "void *"


def test_header_does_not_disguise_uncertain_types():
    value = header({"class_name": "Fixture", "superclass": "UIViewController", "methods": {"methods": [
        {"selector": "unknown", "type_encoding": "?16@0:8", "class_method": False},
        {"selector": "buttonTapped:", "type_encoding": "v24@0:8@16", "class_method": False},
    ]}})
    assert "? inferred/unsupported" in value and "buttonTapped:(id)arg0" in value


@pytest.mark.asyncio
async def test_ui_limits_and_session_scoping(app: Application):
    app.frida.rpc = AsyncMock(return_value={"views": [{"view_id": "process_test:object_1", "class_name": "UIButton", "observed": True}]})
    result = await app.tools.invoke("ui_snapshot", {"device_id": "test", "session_id": "process_test"})
    assert result.ok
    kwargs = app.frida.rpc.call_args.args[-1]
    assert kwargs["depth"] == 8 and kwargs["include_text"] is False
    invalid = await app.tools.invoke("ui_snapshot", {"device_id": "test", "session_id": "process_test", "max_nodes": 100000})
    assert not invalid.ok and invalid.error.code == "INVALID_INPUT"
    app.frida.sessions["test-session"] = ProcessSession("test-session", "test", "dev.iosdecompiler.fixture", 42, SimpleNamespace())
    with pytest.raises(MCPError):
        app.frida.session("another-device", "test-session")
    app.frida.sessions["test-session"].invalidate("process-exited", app.registry)
    with pytest.raises(MCPError):
        app.frida.session("test", "test-session")


@pytest.mark.asyncio
async def test_trace_cursor_reports_overflow_and_process_exit(app: Application):
    session = ProcessSession("test-session", "test", "dev.iosdecompiler.fixture", 42, SimpleNamespace())
    app.frida.sessions[session.id] = session
    for i in range(10):
        session.event({"type": "call", "hook_id": "hook1", "index": i, "password": "should never appear"}, 3)
    session.invalidate("exited", app.registry)
    result = app.frida.events("test", session.id, after=5, limit=2)
    assert result["dropped"] == 7 and len(result["events"]) == 2
    assert result["events"][0]["sequence"] == 8 and not result["active"]
    assert result["events"][0]["password"] == "[REDACTED]"


async def test_screenshot_binary_is_preserved_beyond_text_redaction_limit(app: Application):
    png = b"\x89PNG\r\n\x1a\n" + bytes(300000)
    app.frida.rpc = AsyncMock(return_value={"mime_type": "image/png", "base64": base64.b64encode(png).decode(), "window_id": "process_test:object_1"})
    result = await app.tools.invoke("ui_screenshot", {"device_id": "test", "session_id": "process_test"})
    assert result.ok and "base64" not in result.data
    assert Path(result.data["local_path"]).read_bytes() == png
    assert result.data["bytes"] == len(png)
