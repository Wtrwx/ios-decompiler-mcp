from __future__ import annotations

import gzip
import io
import plistlib
import sys
import tarfile
from pathlib import Path

import pytest

from ios_decompiler_mcp.adapters.debian import inspect_package
from ios_decompiler_mcp.adapters.process import run_process
from ios_decompiler_mcp.adapters.theos import HookSpec, ProjectSpec, diagnostics
from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.core.errors import MCPError


def make_deb(tmp_path: Path, spec: dict, *, global_injection: bool = False, script: bool = False, script_name: str = "postinst", control_archive: bytes | None = None, trailing_slash: bool = True) -> Path:
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
    members = {"debian-binary": b"2.0\n", "control.tar.gz": control_archive if control_archive is not None else archive(control), "data.tar.gz": archive(payload)}
    output = tmp_path / "fixture.deb"
    # Write the common ar format required by deb(5), independent of host ar defaults.
    # https://manpages.debian.org/testing/dpkg-dev/deb.5.en.html
    with output.open("wb") as package:
        package.write(b"!<arch>\n")
        for name, content in members.items():
            filename = name + "/" if trailing_slash else name
            header = f"{filename:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(content):<10}`\n"
            package.write(header.encode("ascii"))
            package.write(content)
            if len(content) % 2:
                package.write(b"\n")
    return output


def test_project_is_editable_and_application_scoped(app: Application, project):
    path = Path(project["path"])
    assert plistlib.loads((path / "FixtureTitle.plist").read_bytes()) == {"Filter": {"Bundles": ["dev.iosdecompiler.fixture"]}}
    makefile = (path / "Makefile").read_text()
    assert "THEOS_PACKAGE_SCHEME = rootless" in makefile and "install::" not in makefile
    hook = HookSpec(class_name="FixtureViewController", selector="viewDidAppear:", type_encoding="v20@0:8B16", accessibility_identifier="fixture.button", title='Changed "Title"')
    result = app.theos.write_hook(project["project_id"], hook)
    assert not result["validated"]
    assert "dispatch_get_main_queue" in result["source"] and "viewDidAppear:(BOOL)arg0" in result["source"]
    assert '@"Changed \\"Title\\""' in result["source"]


@pytest.mark.parametrize("trailing_slash", [False, True])
def test_package_inspection_rejects_global_injection_and_scripts(tmp_path: Path, trailing_slash: bool):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.iosdecompiler.fixture.title", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec, trailing_slash=trailing_slash)
    metadata = inspect_package(package, spec, 1048576)
    assert metadata["architecture"] == "iphoneos-arm64"
    make_deb(tmp_path, spec, global_injection=True, trailing_slash=trailing_slash)
    with pytest.raises(MCPError, match="exactly"):
        inspect_package(package, spec, 1048576)
    make_deb(tmp_path, spec, script=True, trailing_slash=trailing_slash)
    with pytest.raises(MCPError, match="scripts"):
        inspect_package(package, spec, 1048576)
    make_deb(tmp_path, spec, script=True, script_name="././postinst", trailing_slash=trailing_slash)
    with pytest.raises(MCPError, match="scripts"):
        inspect_package(package, spec, 1048576)


@pytest.mark.parametrize(("start", "end", "replacement", "code"), [
    pytest.param(0, 8, b"invalid\n", "INVALID_INPUT", id="signature"),
    pytest.param(66, 68, b"xx", "INVALID_INPUT", id="header-trailer"),
    pytest.param(8, 24, b"#1/12".ljust(16), "INVALID_INPUT", id="extended-name"),
    pytest.param(56, 66, b"-1".ljust(10), "INVALID_INPUT", id="negative-size"),
    pytest.param(56, 66, b"9999999999", "LIMIT_EXCEEDED", id="oversized-member"),
])
def test_malformed_debian_archive_is_rejected(tmp_path: Path, start: int, end: int, replacement: bytes, code: str):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.iosdecompiler.fixture.title", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec)
    content = package.read_bytes()
    package.write_bytes(content[:start] + replacement + content[end:])
    with pytest.raises(MCPError) as rejected:
        inspect_package(package, spec, 1048576)
    assert rejected.value.code == code


@pytest.mark.parametrize("length", [7, 67, 71, -1])
def test_truncated_debian_archive_is_rejected(tmp_path: Path, length: int):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.iosdecompiler.fixture.title", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec)
    package.write_bytes(package.read_bytes()[:length])
    with pytest.raises(MCPError) as rejected:
        inspect_package(package, spec, 1048576)
    assert rejected.value.code == "INVALID_INPUT"


def test_duplicate_debian_member_names_are_rejected(tmp_path: Path):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.iosdecompiler.fixture.title", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec)
    content = package.read_bytes()
    # The same logical member with and without its optional trailing slash.
    duplicate = b"debian-binary".ljust(16) + content[24:72]
    package.write_bytes(content + duplicate)
    with pytest.raises(MCPError, match="Duplicate"):
        inspect_package(package, spec, 1048576)


def test_unsafe_abi_and_makefile_injection_rejected():
    with pytest.raises(ValueError):
        ProjectSpec(name="x\ninstall:", package_id="dev.test", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0")
    with pytest.raises(ValueError):
        HookSpec(class_name="Fixture", selector="value", type_encoding="?16@0:8", behavior="return_constant", constant=1)
    with pytest.raises(ValueError):
        ProjectSpec(name="X", package_id="dev.test", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="14.0")


def test_compressed_metadata_is_bounded_before_tar_parsing(tmp_path: Path):
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.iosdecompiler.fixture.title", bundle_id="dev.iosdecompiler.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0").model_dump()
    package = make_deb(tmp_path, spec, control_archive=gzip.compress(bytes(5 * 1024 * 1024)))
    with pytest.raises(MCPError) as rejected:
        inspect_package(package, spec, 65536)
    assert rejected.value.code == "LIMIT_EXCEEDED"


def test_compiler_diagnostics():
    parsed = diagnostics("\x1b[31mTweak.xm:12:4: error: unknown type name 'Thing'\x1b[0m\nmake: *** [build] Error 1")
    assert parsed[0]["line"] == 12 and parsed[0]["column"] == 4
    assert parsed[1]["severity"] == "error"


@pytest.mark.asyncio
async def test_build_process_timeout_is_bounded(tmp_path: Path):
    with pytest.raises(MCPError, match="terminated"):
        await run_process([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, 0.05)
