from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from ios_decompiler_mcp.adapters.macho import correlate
from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.config import StrictModel
from ios_decompiler_mcp.core.errors import Code, MCPError
from ios_decompiler_mcp.tools.models import Identifier, MethodRequest, Page


class OpenBinary(StrictModel):
    path: Path
    architecture: Literal["arm64", "arm64e", "x86_64"] | None = None
    binary_path: Path | None = None


class IDARequest(StrictModel):
    ida_session_id: Identifier


class IDAPage(IDARequest, Page):
    pass


class Function(IDAPage):
    address: str = Field(min_length=1, max_length=1024)


class Decompile(Function):
    text_offset: int = Field(default=0, ge=0, le=10000000)


class Xrefs(Function):
    direction: Literal["to", "from"] = "to"


class Symbols(IDAPage):
    query: str = Field(default="", max_length=255)


class RuntimeAddress(MethodRequest):
    ida_session_id: Identifier


def register(app: Application) -> None:
    async def open_binary(request: OpenBinary) -> dict[str, Any]:
        path = app.permissions.local_path(request.path, must_exist=True)
        binary = app.permissions.local_path(request.binary_path, must_exist=True) if request.binary_path else None
        return await app.ida.open(path, request.architecture, binary)

    async def metadata(request: IDARequest) -> dict[str, Any]:
        session = app.ida.session(request.ida_session_id)
        return {"metadata": session.metadata, "macho": session.macho}

    async def functions(request: IDAPage) -> dict[str, Any]:
        return await app.ida.rpc(request.ida_session_id, "list_functions", request.model_dump(exclude={"ida_session_id"}))

    async def function(request: Function) -> dict[str, Any]:
        return await app.ida.rpc(request.ida_session_id, "get_function", request.model_dump(exclude={"ida_session_id"}))

    async def decompile(request: Decompile) -> dict[str, Any]:
        return await app.ida.rpc(request.ida_session_id, "decompile", request.model_dump(exclude={"ida_session_id"}))

    async def xrefs(request: Xrefs) -> dict[str, Any]:
        return await app.ida.rpc(request.ida_session_id, "xrefs", request.model_dump(exclude={"ida_session_id"}))

    async def symbols(request: Symbols) -> dict[str, Any]:
        return await app.ida.rpc(request.ida_session_id, "search_symbols", request.model_dump(exclude={"ida_session_id"}))

    async def resolve(request: RuntimeAddress) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        session = app.ida.session(request.ida_session_id)
        if not session.macho or not session.macho.get("database_identity_verified"):
            raise MCPError(Code.IDENTITY_MISMATCH, "This database has no independently verified Mach-O input identity; provide binary_path when opening an existing database")
        evidence = await app.frida.rpc(request.device_id, request.session_id, "get_method_implementation", request.model_dump(exclude={"device_id", "session_id", "ida_session_id"}))
        image = evidence.get("image")
        if not image:
            raise MCPError(Code.IDENTITY_MISMATCH, "The observed IMP has no known loaded-module boundary")
        mapping = correlate(session.macho, image, session.metadata["image_base"])
        static_function = await app.ida.rpc(request.ida_session_id, "get_function", {"address": mapping["ida_address"], "limit": 1})
        return {"mapping": mapping, "function": static_function, "runtime_evidence": evidence, "function_contains_imp": True,
            "exact_function_entry": int(static_function["address"], 0) == int(mapping["ida_address"], 0), "note": "Address correlation does not prove Objective-C dispatch behavior or reconstruct stripped names"}

    async def close(request: IDARequest) -> dict[str, Any]:
        return await app.ida.close_session(request.ida_session_id)

    app.tools.add("ida_open_binary", OpenBinary, open_binary, "Open a workspace Mach-O or existing IDB in an isolated licensed IDA Pro 9+ worker; analyze a managed copy.", timeout=app.settings.build_timeout + 10)
    app.tools.add("ida_get_metadata", IDARequest, metadata, "Retrieve binary UUID, architecture, segments and verified database input identity.")
    app.tools.add("ida_list_functions", IDAPage, functions, "List analyzed functions with pagination.")
    app.tools.add("ida_get_function", Function, function, "Retrieve function bounds, name and bounded disassembly by address or symbol.")
    app.tools.add("ida_decompile", Decompile, decompile, "Retrieve paginated inferred pseudocode when Hex-Rays is licensed for this architecture.")
    app.tools.add("ida_get_xrefs", Xrefs, xrefs, "Query bounded code/data references to or from a symbol/address.")
    app.tools.add("ida_search_symbols", Symbols, symbols, "Search symbols including Objective-C selector/class references; stripped names remain unknown.")
    app.tools.add("ida_resolve_runtime_address", RuntimeAddress, resolve, "Correlate an observed runtime IMP only when Mach-O UUID, CPU architecture, database SHA-256 and image segment evidence match.")
    app.tools.add("ida_close", IDARequest, close, "Save and close this managed analysis copy and release its worker.", read_only=False)
