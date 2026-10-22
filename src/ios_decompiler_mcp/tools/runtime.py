from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import Field

from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.core.objc_types import header
from ios_decompiler_mcp.tools.models import ClassRequest, MethodRequest, SessionPage


class SearchClasses(SessionPage):
    query: str = Field(default="", max_length=255)


class ClassPage(ClassRequest):
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=100, ge=1, le=500)


class Methods(ClassPage):
    include_inherited: bool = False
    class_method: bool | None = None


class ObjectRequest(SessionPage):
    object_id: str = Field(min_length=1, max_length=255)


def register(app: Application) -> None:
    def rpc(method: str) -> Callable[[Any], Awaitable[dict[str, Any]]]:
        async def invoke(request: Any) -> dict[str, Any]:
            app.permissions.device(request.device_id)
            return await app.frida.rpc(request.device_id, request.session_id, method, request.model_dump(exclude={"device_id", "session_id"}))
        return invoke

    async def generate_header(request: ClassPage) -> dict[str, Any]:
        data = await app.frida.rpc(request.device_id, request.session_id, "dump_class", request.model_dump(exclude={"device_id", "session_id"}))
        return {"header": header(data), "truncated": data.get("methods", {}).get("next_offset") is not None, "source": "observed_runtime_metadata"}

    app.tools.add("objc_generate_header", ClassPage, generate_header, "Generate an Objective-C header with explicit uncertainty annotations from live class metadata.")
    definitions: list[tuple[str, type[ClassPage] | type[SearchClasses] | type[Methods] | type[ObjectRequest] | type[MethodRequest], str, str]] = [
        ("objc_search_classes", SearchClasses, "search_classes", "Search registered Objective-C classes with pagination."),
        ("objc_dump_class", ClassPage, "dump_class", "Inspect class hierarchy, protocols, method encodings, properties and ivars."),
        ("objc_get_methods", Methods, "get_methods", "List instance/class method metadata and IMP/image identities."),
        ("objc_get_properties", ClassPage, "get_properties", "Enumerate declared property attributes without reading property values."),
        ("objc_get_ivars", ClassPage, "get_ivars", "Enumerate ivar names, type encodings and offsets without dumping contents."),
        ("objc_inspect_object", ObjectRequest, "inspect_object", "Inspect a session-scoped object's class and metadata; never invoke arbitrary getters."),
        ("objc_find_instances", ClassPage, "find_instances", "Perform bounded best-effort heap instance discovery; may pause the target."),
        ("objc_get_method_implementation", MethodRequest, "get_method_implementation", "Retrieve an observed method signature, IMP and loaded Mach-O identity."),
    ]
    for name, model, operation, description in definitions:
        app.tools.add(name, model, rpc(operation), description)
