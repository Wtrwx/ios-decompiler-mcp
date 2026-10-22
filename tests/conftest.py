from __future__ import annotations

from pathlib import Path

import pytest

from flex_mcp.adapters.theos import ProjectSpec
from flex_mcp.app import Application
from flex_mcp.config import DeviceConfig, Settings
from flex_mcp.server import create_server


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(workspace=tmp_path, state_dir=tmp_path / ".state", devices={"test": DeviceConfig(host="127.0.0.1", allowed_apps=["dev.flex.fixture"], frida_device_id="test-usb")})


@pytest.fixture
def app(settings: Settings):
    instance = Application(settings)
    create_server(instance)
    yield instance
    instance.registry.close()


@pytest.fixture
def project(app: Application, tmp_path: Path):
    theos = tmp_path / "theos"
    (theos / "makefiles").mkdir(parents=True)
    (theos / "makefiles/common.mk").touch()
    (theos / "sdks/iPhoneOS16.5.sdk").mkdir(parents=True)
    app.settings.theos = theos
    spec = ProjectSpec(name="FixtureTitle", package_id="dev.flex.fixture.title", bundle_id="dev.flex.fixture", architectures=["arm64"], sdk_version="16.5", deployment_target="15.0")
    return app.theos.create(spec)
