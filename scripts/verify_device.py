"""Read-only physical-device checks through the real MCP stdio transport.

The application must already be running. No launch, package installation,
UI action, argument replacement or text capture is performed. A temporary
observation hook is removed before detaching. Reports stay in the private state
directory; they contain runtime/UI metadata rather than application text.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import frida
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ios_decompiler_mcp.config import Settings


async def verify(config: Path, device_id: str, bundle_id: str) -> None:
    settings = Settings.load(config)
    if bundle_id not in settings.devices[device_id].allowed_apps:
        raise ValueError("Select an explicitly allowlisted application")
    report: dict[str, Any] = {
        "started_at": datetime.now(UTC).isoformat(),
        "device_id": device_id,
        "bundle_id": bundle_id,
        "mode": "read_only_with_temporary_observation_hook",
        "host_frida_version": frida.__version__,
        "checks": [],
    }
    destination = settings.state_dir / "hardware-reports"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = destination / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".json")

    def save() -> None:
        with path.open("w") as stream:
            path.chmod(0o600)
            json.dump(report, stream, ensure_ascii=False, indent=2)

    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ios_decompiler_mcp.server", "--config", str(config.resolve())],
        cwd=str(settings.workspace),
        env=dict(os.environ),
    )
    try:
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = (await client.list_tools()).tools
                report["tool_count"] = len(tools)
                print(f"MCP discovered {len(tools)} tools", flush=True)

                async def call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
                    result = await client.call_tool(name, arguments)
                    structured = result.structuredContent
                    if not isinstance(structured, dict):
                        raise AssertionError(f"{name} returned no structured result")
                    report["checks"].append({"tool": name, "result": structured})
                    save()
                    if not structured.get("ok"):
                        print(f"FAIL {name}: {json.dumps(structured.get('error'))}", flush=True)
                        raise RuntimeError(f"{name} failed")
                    print(f"PASS {name} ({structured.get('elapsed_ms')} ms)", flush=True)
                    return structured.get("data") or {}

                await call("device_connect", {"device_id": device_id})
                apps = await call("device_list_apps", {"device_id": device_id})
                selected = next(app for app in apps["applications"] if app["bundle_id"] == bundle_id)
                assert selected["pid"], "Open the selected app on the device first"
                await call("device_list_processes", {"device_id": device_id})
                attached = await call("frida_attach", {"device_id": device_id, "bundle_id": bundle_id, "pid": selected["pid"]})
                session = {"device_id": device_id, "session_id": attached["session_id"]}
                hook_id: str | None = None
                try:
                    window_info = await call("ui_get_windows", session)
                    assert window_info["windows"], "No UIKit windows observed"
                    snapshot = await call("ui_snapshot", {**session, "depth": 12, "max_nodes": 512, "limit": 500, "include_text": False})
                    assert snapshot["views"]
                    assert all("text" not in view for view in snapshot["views"])
                    candidates = [view for view in snapshot["views"] if not view["hidden"] and view["alpha"] > 0]
                    chosen = next((view for view in candidates if view.get("is_button")), candidates[0])
                    view_args = {**session, "view_id": chosen["view_id"], "include_text": False, "limit": 50}
                    await call("ui_inspect_view", view_args)
                    await call("ui_get_constraints", view_args)
                    await call("ui_get_responder_chain", view_args)
                    found = await call("ui_find_views", {**session, "class_name": chosen["class_name"], "depth": 12, "max_nodes": 512, "limit": 50})
                    assert found["views"]
                    key_window = next((window for window in window_info["windows"] if window["key_window"]), window_info["windows"][0])
                    frame = key_window["frame"]
                    await call("ui_hit_test", {**session, "window_id": key_window["view_id"], "x": frame["width"] / 2, "y": frame["height"] / 2})
                    class_name = chosen.get("controller", {}).get("class_name") if chosen.get("controller") else chosen["class_name"]
                    class_args = {**session, "class_name": class_name, "limit": 30}
                    classes = await call("objc_search_classes", {**session, "query": class_name, "limit": 30})
                    assert class_name in classes["classes"]
                    await call("objc_dump_class", class_args)
                    await call("objc_get_methods", class_args)
                    await call("objc_get_properties", class_args)
                    await call("objc_get_ivars", class_args)
                    await call("objc_generate_header", class_args)
                    await call("objc_inspect_object", {**session, "object_id": chosen["view_id"], "limit": 30})
                    # App-generated subclasses may declare no properties/ivars.
                    # Exercise the native entry readers with a UIKit base class.
                    base_class = {**session, "class_name": "UIView", "limit": 10}
                    assert (await call("objc_get_properties", base_class))["properties"]
                    assert (await call("objc_get_ivars", base_class))["ivars"]
                    # A custom button may use manual frames. Look for a real
                    # nonempty constraint list without capturing labels/text.
                    report["nonempty_constraints_observed"] = False
                    for candidate in candidates[:16]:
                        constraint_result = await call("ui_get_constraints", {**session, "view_id": candidate["view_id"], "limit": 10})
                        if constraint_result["constraints"]:
                            report["nonempty_constraints_observed"] = True
                            break
                    method = {**session, "class_name": "UIWindow", "selector": "isKeyWindow"}
                    implementation = await call("objc_get_method_implementation", method)
                    assert implementation["image"]["uuid"], "No Mach-O UUID was observed"
                    hook = await call("frida_trace_method", {**method, "capture_return": True, "backtrace": True, "max_events": 24})
                    hook_id = hook["hook_id"]
                    await call("ui_get_windows", session)
                    events = await call("frida_get_events", {**session, "hook_id": hook_id, "limit": 50})
                    assert events["events"], "No calls were observed during a window query"
                    await call("frida_get_backtrace", {**session, "hook_id": hook_id, "limit": 50})
                    await call("frida_export_trace", {**session, "hook_id": hook_id, "limit": 50})
                    hooks = await call("frida_list_hooks", session)
                    assert any(hook["calls"] > 0 for hook in hooks["hooks"])
                    await call("frida_enable_hook", {**session, "hook_id": hook_id, "enabled": False})
                    await call("frida_enable_hook", {**session, "hook_id": hook_id, "enabled": True})
                    await call("frida_unhook", {**session, "hook_id": hook_id})
                    hook_id = None
                    assert not (await call("frida_list_hooks", session))["hooks"]
                    report["inspection_passed"] = True
                finally:
                    try:
                        if hook_id is not None:
                            await call("frida_unhook", {**session, "hook_id": hook_id})
                    finally:
                        await call("frida_detach", session)
                final_apps = await call("device_list_apps", {"device_id": device_id})
                final = next(app for app in final_apps["applications"] if app["bundle_id"] == bundle_id)
                assert final["pid"] == selected["pid"], "Target PID changed during inspection"
                report["same_pid_after_detach"] = True
                report["passed"] = True
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        save()
        print(f"Report: {path}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--bundle", required=True)
    arguments = parser.parse_args()
    try:
        asyncio.run(verify(arguments.config, arguments.device, arguments.bundle))
    except Exception as error:
        parser.exit(1, f"Hardware verification failed ({type(error).__name__}); see the saved report and failing tool above.\n")
