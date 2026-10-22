from __future__ import annotations

import json
import struct
import sys

import pytest

from ios_decompiler_mcp.adapters.macho import correlate, inspect_macho
from ios_decompiler_mcp.core.errors import MCPError


@pytest.fixture
def metadata():
    return {"uuid": "e0804157-707d-4a2b-a0c2-abce6c07077b", "architecture": "arm64e", "image_base": 0x100000000,
        "segments": [{"name": "__TEXT", "virtual_address": 0x100000000, "virtual_size": 0x4000}]}


def test_aslr_uuid_architecture_and_rebased_ida_mapping(metadata):
    runtime = {"uuid": metadata["uuid"], "architecture": "arm64e", "canonical_address": "0x104001234", "runtime_base": "0x104000000", "size": 0x4000, "pac_stripped": True}
    mapping = correlate(metadata, runtime, 0x200000000)
    assert mapping["static_virtual_address"] == "0x100001234"
    assert mapping["ida_address"] == "0x200001234" and mapping["slide"] == "0x4000000"
    assert mapping["pac_stripped"] and not mapping["semantic_match_asserted"]
    for changed in ({"uuid": None}, {"uuid": "different"}, {"architecture": "arm64"}, {"canonical_address": "0x104010000"}):
        with pytest.raises(MCPError) as rejected:
            correlate(metadata, {**runtime, **changed}, 0x200000000)
        assert rejected.value.code == "IDENTITY_MISMATCH"


def test_thin_macho_copy_preserves_original_bytes(tmp_path):
    source = tmp_path / "thin.dylib"
    source.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 6, 0, 0, 0, 0) + bytes(4096))
    output = tmp_path / "copy.dylib"
    metadata = inspect_macho(source, "arm64", output)
    assert metadata["architecture"] == "arm64"
    assert output.read_bytes() == source.read_bytes()


async def test_ida_worker_protocol_isolation_and_invalidation(app, tmp_path, monkeypatch):
    installation = tmp_path / "IDA"
    (installation / "idalib/python/idapro").mkdir(parents=True)
    app.settings.ida_directory = installation
    path = tmp_path / "fixture.i64"
    path.write_bytes(b"TEST DATABASE - no SDK used")
    original_spawn = __import__("asyncio").create_subprocess_exec
    script = '''
import json, sys
print(json.dumps({"ready": True, "metadata": {"image_base": 0}}), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    if request["operation"] == "close": break
    response = {"id": request["id"], "result": {"functions": []}}
    if request["operation"] == "out_of_sync": response["id"] = "wrong"
    print(json.dumps(response), flush=True)
'''

    async def spawn(*args, **kwargs):
        # Substitute only the licensed external SDK worker, exercising the actual
        # supervisor's subprocess pipes, copied database, timeouts and cleanup.
        return await original_spawn(sys.executable, "-u", "-c", script, **kwargs)

    monkeypatch.setattr("ios_decompiler_mcp.adapters.ida.asyncio.create_subprocess_exec", spawn)
    opened = await app.ida.open(path)
    assert opened["macho"] is None
    assert opened["database_copy"] != str(path)
    assert await app.ida.rpc(opened["ida_session_id"], "list_functions") == {"functions": []}
    with pytest.raises(MCPError) as out_of_sync:
        await app.ida.rpc(opened["ida_session_id"], "out_of_sync")
    assert out_of_sync.value.code == "IDA_ERROR"
    with pytest.raises(MCPError):
        app.ida.session(opened["ida_session_id"])
    assert json.loads(app.registry.db.execute("SELECT data FROM records WHERE id=?", (opened["ida_session_id"],)).fetchone()[0])["metadata"] == {"image_base": 0}


async def test_ida_is_optional_and_unavailable_is_structured(app, tmp_path):
    app.settings.ida_directory = tmp_path / "missing"
    binary = tmp_path / "anything"
    binary.touch()
    result = await app.tools.invoke("ida_open_binary", {"path": str(binary)})
    assert not result.ok and result.error.code == "UNAVAILABLE"
