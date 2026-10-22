from __future__ import annotations

import gzip
import io
import plistlib
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from flex_mcp.adapters.debian import inspect_package
from flex_mcp.adapters.process import run_process
from flex_mcp.adapters.theos import HookSpec, ProjectSpec, diagnostics
from flex_mcp.app import Application
from flex_mcp.core.errors import FlexError


def make_deb(tmp_path: Path, spec: dict, *, global_injection: bool = False, script: bool = False, script_name: str = "postinst") -> Path:
    def archive(files):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            for name, content in files.items():
                member = tarfile.TarInfo("./" + name)
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        return stream.getvalue()
    control = {"control": f'Package: {spec["package_id"]}\nVersion: {spec["version"]}\nArchitecture: {"iphoneos-arm64" if spec["rootless"] else "iphoneos-arm"}\n'.encode()}
    if script:
        control[script_name] = b"#!/bin/sh\nexit 0\n"
    prefix = "var/jb/" if spec["rootless"] else ""
    base = prefix + "Library/MobileSubstrate/DynamicLibraries/" + spec["name"]
    payload = {base + ".dylib": b"TEST-ONLY-DYLIB", base + ".plist": plistlib.dumps({"Filter": {"Bundles": ["com.apple.springboard" if global_injection else spec["bundle_id"]]}})}
    for name, content in {"debian-binary": b"2.0\n", "control.tar.gz": archive(control), "data.tar.gz": archive(payload)}.items():
        (tmp_path / name).write_bytes(content)
    output = tmp_path / "fixture.deb"
    subprocess.run(["ar", "rc", str(output), "debian-binary", "control.tar.gz", "data.tar.gz"], cwd=tmp_path, check=True, capture_output=True)
    return output


def test_project_is_editable_and_application_scoped(app: Application, project):
    path = Path(project["path"])
    assert plistlib.loads((path / "FixtureTitle.plist").read_bytes()) == {"Filter": {"Bundles": ["dev.flex.fixture"]}}
    makefile = (path / "Makefile").read_text()
    assert "THEOS_PACKAGE_SCHEME = rootless" in makefile and "install::" not in makefile
    hook = HookSpec(class_name="FixtureViewController", selector="viewDidAppear:", type_encoding="v20@0:8B16", accessibility_identifier="fixture.button", title='Changed "Title"')
    result = app.theos.write_hook(project["project_id"], hook)
    assert not result["validated"]
    assert "dispatch_get_main_queue" in result["source"] and "viewDidAppear:(BOOL)arg0" in result["source"]
    assert '@"Changed \\"Title\\""' in result["source"]


def test_package_inspection_rejects_global_injection_and_scripts(tmp_path: Path):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.flex.fixture.title", bundle_id="dev.flex.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec)
    metadata = inspect_package(package, spec, 1048576)
    assert metadata["architecture"] == "iphoneos-arm64"
    make_deb(tmp_path, spec, global_injection=True)
    with pytest.raises(FlexError, match="exactly"):
        inspect_package(package, spec, 1048576)
    make_deb(tmp_path, spec, script=True)
    with pytest.raises(FlexError, match="scripts"):
        inspect_package(package, spec, 1048576)
    make_deb(tmp_path, spec, script=True, script_name="././postinst")
    with pytest.raises(FlexError, match="scripts"):
        inspect_package(package, spec, 1048576)


def test_unsafe_abi_and_makefile_injection_rejected():
    with pytest.raises(ValueError):
        ProjectSpec(name="x\ninstall:", package_id="dev.test", bundle_id="dev.flex.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0")
    with pytest.raises(ValueError):
        HookSpec(class_name="Fixture", selector="value", type_encoding="?16@0:8", behavior="return_constant", constant=1)
    with pytest.raises(ValueError):
        ProjectSpec(name="X", package_id="dev.test", bundle_id="dev.flex.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="14.0")


def test_compressed_metadata_is_bounded_before_tar_parsing(tmp_path: Path):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.flex.fixture.title", bundle_id="dev.flex.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec)
    (tmp_path / "control.tar.gz").write_bytes(gzip.compress(bytes(5 * 1024 * 1024)))
    subprocess.run(["ar", "r", str(package), "control.tar.gz"], cwd=tmp_path, check=True, capture_output=True)
    with pytest.raises(FlexError) as rejected:
        inspect_package(package, spec, 65536)
    assert rejected.value.code == "LIMIT_EXCEEDED"


def test_compiler_diagnostics():
    parsed = diagnostics("\x1b[31mTweak.xm:12:4: error: unknown type name 'Thing'\x1b[0m\nmake: *** [build] Error 1")
    assert parsed[0]["line"] == 12 and parsed[0]["column"] == 4
    assert parsed[1]["severity"] == "error"


@pytest.mark.asyncio
async def test_build_process_timeout_is_bounded(tmp_path: Path):
    with pytest.raises(FlexError, match="terminated"):
        await run_process([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, 0.05)
