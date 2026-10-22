from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class DeviceConfig(StrictModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "mobile"
    client_keys: list[Path] = Field(default_factory=list, repr=False)
    known_hosts: Path = Path("~/.ssh/known_hosts")
    allowed_apps: list[str] = Field(default_factory=list)
    frida_device_id: str | None = None
    frida_remote: str | None = None
    frida_server_version: str | None = None
    jailbreak_prefix: str | None = None
    staging_directory: str = "/tmp/flex-mcp"
    download_roots: list[str] = Field(default_factory=lambda: ["/tmp/flex-mcp"])
    crash_roots: list[str] = Field(default_factory=lambda: ["/var/mobile/Library/Logs/CrashReporter", "/Library/Logs/CrashReporter"])

    @field_validator("host", "username")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        if any(ord(c) < 32 for c in value):
            raise ValueError("control characters are not permitted")
        return value

    @field_validator("staging_directory", "jailbreak_prefix")
    @classmethod
    def absolute_remote_path(cls, value: str | None) -> str | None:
        if value is not None and (not value.startswith("/") or ".." in value.split("/")):
            raise ValueError("use an absolute normalized device path")
        return value

    @model_validator(mode="after")
    def frida_transport(self) -> DeviceConfig:
        if self.frida_device_id and self.frida_remote:
            raise ValueError("select a Frida device ID or remote address, not both")
        return self


class Settings(StrictModel):
    state_dir: Path = Path(".flex-mcp")
    workspace: Path = Field(default_factory=Path.cwd)
    devices: dict[str, DeviceConfig] = Field(default_factory=dict)
    operation_timeout: float = Field(default=30, ge=1, le=300)
    build_timeout: float = Field(default=180, ge=5, le=1800)
    event_limit: int = Field(default=1000, ge=1, le=10000)
    max_sessions: int = Field(default=8, ge=1, le=64)
    max_jobs: int = Field(default=4, ge=1, le=16)
    max_transfer_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    theos: Path | None = None
    ida_directory: Path | None = None
    ida_python: Path | None = None

    @model_validator(mode="after")
    def normalize_paths(self) -> Settings:
        self.workspace = self.workspace.expanduser().resolve()
        self.state_dir = self.state_dir.expanduser()
        if not self.state_dir.is_absolute():
            self.state_dir = self.workspace / self.state_dir
        self.state_dir = self.state_dir.resolve()
        if self.theos is None and os.environ.get("THEOS"):
            self.theos = Path(os.environ["THEOS"])
        if self.theos:
            self.theos = self.theos.expanduser().resolve()
        return self

    @classmethod
    def load(cls, path: Path | None = None) -> Settings:
        chosen = path or (Path(os.environ["FLEX_MCP_CONFIG"]) if os.environ.get("FLEX_MCP_CONFIG") else None)
        if chosen is None:
            return cls()
        with chosen.open("rb") as stream:
            return cls.model_validate(tomllib.load(stream))
