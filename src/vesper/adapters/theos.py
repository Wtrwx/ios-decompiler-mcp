from __future__ import annotations

import asyncio
import json
import os
import platform
import plistlib
import re
import shutil
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from vesper.adapters.process import run_process
from vesper.config import Settings, StrictModel
from vesper.core.errors import Code, MCPError
from vesper.core.evidence import redact
from vesper.core.objc_types import signature
from vesper.core.permissions import sha256
from vesper.core.registry import Registry, new_id
from vesper.tools.models import ClassName, Identifier, Selector


class ProjectSpec(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    package_id: str = Field(pattern=r"^[a-z0-9][a-z0-9+.-]{2,127}$")
    bundle_id: Identifier
    version: str = Field(default="0.1.0", pattern=r"^[0-9][A-Za-z0-9.+~]{0,63}$")
    rootless: bool = True
    architectures: list[Literal["arm64", "arm64e"]] = Field(min_length=1, max_length=2)
    sdk_version: str = Field(pattern=r"^\d+\.\d+(?:\.\d+)?$")
    deployment_target: str = Field(pattern=r"^\d+\.\d+(?:\.\d+)?$")

    @model_validator(mode="after")
    def target_supported(self) -> ProjectSpec:
        target = tuple(map(int, self.deployment_target.split(".")))
        sdk = tuple(map(int, self.sdk_version.split(".")))
        if target > sdk or (self.rootless and target < (15, 0)):
            raise ValueError("deployment target must be supported by SDK and rootless requires iOS 15+")
        if "arm64e" in self.architectures and platform.system() != "Darwin":
            raise ValueError("new arm64e ABI requires an appropriate Apple toolchain on macOS")
        return self


class HookSpec(StrictModel):
    class_name: ClassName
    selector: Selector
    class_method: bool = False
    type_encoding: str = Field(min_length=1, max_length=1024)
    behavior: Literal["set_button_title", "log_call", "return_constant"] = "set_button_title"
    accessibility_identifier: str | None = Field(default=None, max_length=255)
    title: str | None = Field(default=None, max_length=512)
    constant: int | bool | None = None

    @field_validator("title", "accessibility_identifier")
    @classmethod
    def no_nul(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("NUL cannot be embedded in an Objective-C literal")
        return value

    @model_validator(mode="after")
    def recipe_parameters(self) -> HookSpec:
        declaration, certain = signature(self.selector, self.type_encoding, self.class_method)
        if not certain:
            raise ValueError("automated generation requires a fully understood method ABI")
        if self.behavior == "set_button_title":
            if self.class_method or not declaration.startswith("- (void)"):
                raise ValueError("button-title recipe requires a void instance lifecycle method")
            if self.title is None or not self.accessibility_identifier:
                raise ValueError("button-title recipe requires a title and accessibility identifier")
        if self.behavior == "return_constant":
            if self.constant is None or not re.match(r"^[+-] \((?:BOOL|signed char|unsigned char|short|unsigned short|int|unsigned int|long|unsigned long|long long|unsigned long long)\)", declaration):
                raise ValueError("constant recipe supports known integer/BOOL return ABIs only")
        return self


def diagnostics(output: str) -> list[dict[str, Any]]:
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
    pattern = re.compile(r"^(.*?):(\d+):(\d+):\s*(fatal error|error|warning|note):\s*(.*)$")
    values = []
    for line in clean.splitlines():
        match = pattern.match(line)
        if match:
            file, row, col, severity, message = match.groups()
            values.append({"file": file, "line": int(row), "column": int(col), "severity": severity, "message": message})
        elif re.search(r"(?:error:|Error \d|ERROR:|fatal:)", line):
            values.append({"severity": "error", "message": line[:2000]})
    return values[:500]


def objc_literal(value: str) -> str:
    return "@" + json.dumps(value, ensure_ascii=False)


_HELPER = """static void VesperApplyTitle(UIView *root, NSString *identifier, NSString *title) {
    if (!root) return;
    NSMutableArray<UIView *> *pending = [NSMutableArray arrayWithObject:root];
    NSUInteger visited = 0;
    while (pending.count && visited++ < 2048) {
        UIView *view = pending.lastObject;
        [pending removeLastObject];
        if ([view isKindOfClass:[UIButton class]] && [view.accessibilityIdentifier isEqualToString:identifier]) {
            [(UIButton *)view setTitle:title forState:UIControlStateNormal];
        }
        [pending addObjectsFromArray:view.subviews];
    }
}
"""


def render_source(hooks: list[HookSpec]) -> str:
    lines = ["#import <UIKit/UIKit.h>", '#include "BuildIdentity.h"',
        '__attribute__((visibility("default"), used)) extern const char VesperBuildID[] = VESPER_BUILD_ID;',
        '__attribute__((visibility("default"), used)) unsigned long VesperInvocationCount = 0;']
    if any(hook.behavior == "set_button_title" for hook in hooks):
        lines.append(_HELPER)
    groups: dict[str, list[HookSpec]] = {}
    for hook in hooks:
        groups.setdefault(hook.class_name, []).append(hook)
    for name, entries in groups.items():
        lines.append(f"%hook {name}")
        for hook in entries:
            declaration, _ = signature(hook.selector, hook.type_encoding, hook.class_method)
            lines.append(declaration + " {")
            returns_void = declaration.startswith(("- (void)", "+ (void)"))
            if hook.behavior == "return_constant":
                lines.append(f"    __atomic_fetch_add(&VesperInvocationCount, 1, __ATOMIC_RELAXED); return {int(hook.constant or 0)};")
            elif hook.behavior == "set_button_title":
                identifier, title = objc_literal(hook.accessibility_identifier or ""), objc_literal(hook.title or "")
                lines.extend(["    %orig;", "    __atomic_fetch_add(&VesperInvocationCount, 1, __ATOMIC_RELAXED);", "    UIViewController *owner = (UIViewController *)self;", "    if ([NSThread isMainThread]) {", f"        VesperApplyTitle(owner.view, {identifier}, {title});", "    } else {", f"        dispatch_async(dispatch_get_main_queue(), ^{{ VesperApplyTitle(owner.view, {identifier}, {title}); }});", "    }"])
            else:
                lines.append("    __atomic_fetch_add(&VesperInvocationCount, 1, __ATOMIC_RELAXED);")
                lines.append("    %orig;" if returns_void else "    return %orig;")
            lines.append("}")
        lines.append("%end")
    return "\n".join(lines) + "\n"


class TheosAdapter:
    def __init__(self, settings: Settings, registry: Registry):
        self.settings, self.registry = settings, registry
        self.locks: dict[str, asyncio.Lock] = {}

    def environment(self) -> dict[str, Any]:
        theos = self.settings.theos
        if theos is None or not (theos / "makefiles/common.mk").is_file():
            raise MCPError(Code.UNAVAILABLE, "Configure an installed Theos directory using THEOS or theos in TOML")
        sdks = []
        roots = [theos / "sdks"]
        developer = os.environ.get("DEVELOPER_DIR")
        if developer:
            roots.append(Path(developer) / "Platforms/iPhoneOS.platform/Developer/SDKs")
        if platform.system() == "Darwin":
            roots.extend(Path("/Applications").glob("Xcode*.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs"))
        for root in roots:
            if root.is_dir():
                for sdk in root.glob("iPhoneOS*.sdk"):
                    match = re.fullmatch(r"iPhoneOS(\d+\.\d+(?:\.\d+)?).sdk", sdk.name)
                    if match:
                        sdks.append({"version": match[1], "path": str(sdk.resolve())})
        sdks.sort(key=lambda value: tuple(map(int, value["version"].split("."))))
        make = shutil.which("gmake") or shutil.which("make")
        if not make or not sdks:
            raise MCPError(Code.UNAVAILABLE, "A make executable and versioned iPhoneOS SDK are required")
        return {"theos": str(theos), "make": make, "sdks": sdks, "host": platform.system(), "arm64e_requires_apple_toolchain": True}

    def project(self, project_id: str) -> dict[str, Any]:
        project = self.registry.get(project_id, "project")
        path = Path(project["path"]).resolve()
        if not path.is_relative_to(self.settings.state_dir / "projects") or not path.is_dir():
            raise MCPError(Code.NOT_ALLOWED, "Project path escaped its managed directory")
        return project

    def create(self, spec: ProjectSpec) -> dict[str, Any]:
        environment = self.environment()
        selected = next((sdk for sdk in environment["sdks"] if sdk["version"] == spec.sdk_version), None)
        if selected is None:
            raise MCPError(Code.INVALID_INPUT, "Requested SDK is not installed", sdk_version=spec.sdk_version)
        project_id = new_id("project")
        path = self.settings.state_dir / "projects" / project_id
        path.mkdir(parents=True, exist_ok=False)
        (path / "Makefile").write_text(
            f"ARCHS = {' '.join(spec.architectures)}\nTARGET = iphone:clang:{spec.sdk_version}:{spec.deployment_target}\n"
            + ("THEOS_PACKAGE_SCHEME = rootless\n" if spec.rootless else "")
            + "include $(THEOS)/makefiles/common.mk\n"
            + f"TWEAK_NAME = {spec.name}\n{spec.name}_FILES = Tweak.xm\n{spec.name}_CFLAGS = -fobjc-arc\n{spec.name}_FRAMEWORKS = UIKit Foundation\n"
            + "include $(THEOS_MAKE_PATH)/tweak.mk\n")
        (path / "control").write_text(f"Package: {spec.package_id}\nName: {spec.name}\nVersion: {spec.version}\nArchitecture: {'iphoneos-arm64' if spec.rootless else 'iphoneos-arm'}\nDescription: App-scoped vesper development tweak\nMaintainer: vesper Operator\nAuthor: vesper Operator\nSection: Tweaks\nDepends: mobilesubstrate\n")
        with (path / f"{spec.name}.plist").open("wb") as stream:
            plistlib.dump({"Filter": {"Bundles": [spec.bundle_id]}}, stream)
        (path / "Tweak.xm").write_text(render_source([]))
        (path / "BuildIdentity.h").write_text('#define VESPER_BUILD_ID "unbuilt"\n')
        (path / "hooks.json").write_text("[]\n")
        data: dict[str, Any] = {"path": str(path), "spec": spec.model_dump(), "hooks": [], "latest_build_id": None}
        self.registry.save(project_id, "project", data)
        return {"project_id": project_id, **data, "files": [str(path / file) for file in ("Makefile", "control", f"{spec.name}.plist", "Tweak.xm", "BuildIdentity.h", "hooks.json")]}

    def write_hook(self, project_id: str, hook: HookSpec, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
        project = self.project(project_id)
        entries = project["hooks"]
        key = (hook.class_name, hook.selector, hook.class_method)
        entry = {"spec": hook.model_dump(), "validation": evidence}
        entries = [item for item in entries if (item["spec"]["class_name"], item["spec"]["selector"], item["spec"]["class_method"]) != key] + [entry]
        source = render_source([HookSpec.model_validate(item["spec"]) for item in entries])
        path = Path(project["path"])
        (path / "Tweak.xm").write_text(source)
        (path / "hooks.json").write_text(json.dumps(entries, indent=2) + "\n")
        data = {"path": project["path"], "spec": project["spec"], "hooks": entries, "latest_build_id": None}
        self.registry.save(project_id, "project", data)
        return {"project_id": project_id, "source_path": str(path / "Tweak.xm"), "source": source, "validated": evidence is not None}

    def fingerprint(self, project_id: str) -> str:
        import hashlib
        project = self.project(project_id)
        path = Path(project["path"])
        digest = hashlib.sha256()
        # Include human edits to all source/config/layout files, excluding generated build output.
        for entry in sorted(path.rglob("*")):
            relative = entry.relative_to(path)
            if any(part in {".theos", "packages", "builds", ".git"} for part in relative.parts) or entry.name == "BuildIdentity.h":
                continue
            if entry.is_symlink():
                raise MCPError(Code.NOT_ALLOWED, "Project sources must not contain symlinks")
            if entry.is_file():
                if entry.stat().st_size > 4 * 1024 * 1024:
                    raise MCPError(Code.LIMIT_EXCEEDED, "Project source file exceeds size limit")
                digest.update(str(relative).encode())
                digest.update(entry.read_bytes())
        return digest.hexdigest()

    async def build(self, project_id: str) -> dict[str, Any]:
        async with self.locks.setdefault(project_id, asyncio.Lock()):
            project = self.project(project_id)
            if not project["hooks"]:
                raise MCPError(Code.INVALID_INPUT, "Add at least one hook before building")
            environment = self.environment()
            source_hash = self.fingerprint(project_id)
            build_id = new_id("build")
            path = Path(project["path"])
            directory = path / "builds" / build_id
            directory.mkdir(parents=True)
            (path / "BuildIdentity.h").write_text(f'#define VESPER_BUILD_ID "{build_id}"\n')
            cache = self.settings.state_dir / "compiler-cache"
            cache.mkdir(parents=True, exist_ok=True)
            result = await run_process([environment["make"], "-C", str(path), "clean", "package", "FINALPACKAGE=1", "THEOS=" + environment["theos"], "THEOS_PACKAGE_DIR=" + str(directory), "THEOS_PACKAGE_BUILD_NAME=", "THEOS_PLATFORM_DEB_COMPRESSION_TYPE=gzip", "THEOS_MODULE_CACHE_PATH=" + str(cache)], path, self.settings.build_timeout, env={**os.environ, "LC_ALL": "C", "NO_COLOR": "1", "CLANG_MODULE_CACHE_PATH": str(cache)})
            log = redact(result["output"])
            (directory / "build.log").write_text(log)
            packages = list(directory.glob("*.deb"))
            success = result["exit_status"] == 0 and len(packages) == 1
            package_path = str(packages[0]) if success else None
            record = {"project_id": project_id, "source_hash": source_hash, "exit_status": result["exit_status"], "success": success,
                "diagnostics": diagnostics(log), "log_path": str(directory / "build.log"), "log": log[-32768:],
                "package_path": package_path, "package_sha256": sha256(packages[0]) if success else None,
                "build_marker": build_id, "spec": project["spec"]}
            self.registry.save(build_id, "build", record, "succeeded" if success else "failed")
            project_data = {k: project[k] for k in ("path", "spec", "hooks")}
            self.registry.save(project_id, "project", {**project_data, "latest_build_id": build_id})
            return {"build_id": build_id, **record}
