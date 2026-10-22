from __future__ import annotations

from typing import Annotated

from pydantic import Field

from ios_decompiler_mcp.config import StrictModel

Identifier = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.-]+$")]
ClassName = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z_$][A-Za-z0-9_.$]*$")]
Selector = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z_][A-Za-z0-9_:]*$")]


class Empty(StrictModel):
    pass


class DeviceRequest(StrictModel):
    device_id: Identifier


class AppRequest(DeviceRequest):
    bundle_id: Identifier


class SessionRequest(DeviceRequest):
    session_id: Identifier


class Page(StrictModel):
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=100, ge=1, le=500)


class SessionPage(SessionRequest, Page):
    pass


class ClassRequest(SessionRequest):
    class_name: ClassName


class MethodRequest(ClassRequest):
    selector: Selector
    class_method: bool = False


class JobRequest(StrictModel):
    job_id: Identifier
