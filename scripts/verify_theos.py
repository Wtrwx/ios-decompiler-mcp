"""Build an actual fixture tweak without contacting or modifying any device."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ios_decompiler_mcp.adapters.theos import HookSpec, ProjectSpec
from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.config import Settings


async def verify() -> None:
    app = Application(Settings())
    try:
        environment = app.theos.environment()
        project = app.theos.create(ProjectSpec(name="DecompilerFixtureTitle", package_id="dev.iosdecompiler.fixture.title", bundle_id="dev.iosdecompiler.fixture",
            architectures=["arm64"], sdk_version=environment["sdks"][-1]["version"], deployment_target="15.0"))
        app.theos.write_hook(project["project_id"], HookSpec(class_name="DecompilerFixtureViewController", selector="viewDidAppear:",
            type_encoding="v20@0:8B16", accessibility_identifier="fixture.button", title="Tweaked"))
        result = await app.theos.build(project["project_id"])
        print(json.dumps(result, indent=2))
        if not result["success"]:
            raise SystemExit(1)
        dylib = Path(project["path"]) / ".theos/obj/arm64/DecompilerFixtureTitle.dylib"
        print("IDA test input:", dylib)
    finally:
        await app.close()


if __name__ == "__main__":
    asyncio.run(verify())
