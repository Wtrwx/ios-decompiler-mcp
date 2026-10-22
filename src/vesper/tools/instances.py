from __future__ import annotations

import time
from typing import Any

from pydantic import Field, model_validator

from vesper.app import Application
from vesper.config import StrictModel
from vesper.core.errors import Code, MCPError
from vesper.core.registry import new_id
from vesper.tools.models import AppRequest, ClassName, Identifier


class ValueOptions(StrictModel):
    field_names: list[str] | None = Field(default=None, max_length=32)
    max_fields: int = Field(default=8, ge=1, le=32)
    max_string_length: int = Field(default=128, ge=1, le=4096)
    max_depth: int = Field(default=1, ge=0, le=3)
    max_items: int = Field(default=5, ge=1, le=20)

    @model_validator(mode='after')
    def bounded_names(self) -> ValueOptions:
        if self.field_names and any(not name or len(name) > 255 for name in self.field_names):
            raise ValueError('Ivar names must have 1..255 characters')
        return self


class QueryInstances(AppRequest, ValueOptions):
    class_name: ClassName | None = None
    object_ids: list[str] | None = Field(default=None, min_length=1, max_length=20)
    include_subclasses: bool = True
    max_instances: int = Field(default=20, ge=1, le=100)
    snapshot_id: Identifier | None = None
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=10, ge=1, le=100)

    @model_validator(mode='after')
    def select_source(self) -> QueryInstances:
        if self.snapshot_id:
            if not self.snapshot_id.startswith('instances_'):
                raise ValueError('Expected an instance snapshot_id from objc_query_instances')
            if self.model_fields_set - {'device_id', 'bundle_id', 'snapshot_id', 'offset', 'limit'}:
                raise ValueError('Cached pages only accept device_id, bundle_id, snapshot_id, offset and limit')
        elif (self.class_name is None) == (self.object_ids is None):
            raise ValueError('Choose class_name for heap discovery or object_ids for direct leased reads')
        if self.object_ids and any(not value or len(value) > 255 for value in self.object_ids):
            raise ValueError('Object handles must have 1..255 characters')
        return self


def register(app: Application) -> None:
    async def query(request: QueryInstances) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        if request.snapshot_id:
            app.snapshots.expire()
            entry = app.snapshots.entries.get(request.snapshot_id)
            if not entry:
                raise MCPError(Code.NOT_FOUND, 'Instance snapshot expired or was evicted; request a live query')
            session = app.frida.session(request.device_id, entry.session_id)
            if session.bundle_id != request.bundle_id:
                raise MCPError(Code.NOT_ALLOWED, 'Instance snapshot belongs to another application')
            snapshot_id, session_id, reused = request.snapshot_id, session.id, True
        else:
            attached = await app.frida.attach(request.device_id, request.bundle_id)
            session_id, reused = attached['session_id'], attached.get('reused', False)
            snapshot_id, started = new_id('instances'), time.monotonic()
            args = request.model_dump(exclude={'device_id', 'bundle_id', 'snapshot_id', 'max_instances', 'offset', 'limit'})
            try:
                result = await app.frida.rpc(request.device_id, session_id, 'inspect_objects' if request.object_ids else 'find_instances',
                    {**args, 'limit': request.max_instances, 'include_values': True, '_input_handles': request.object_ids or [],
                     '_lease_id': snapshot_id, '_lease_ttl': app.settings.snapshot_ttl})
                rows = result.pop('instances', [])
                app.snapshots.store(snapshot_id, request.device_id, session_id, {**result, 'views': rows,
                    'truncated': result.get('limit_reached', False)}, started)
            except BaseException:
                app.frida.release_lease(session_id, snapshot_id)
                raise
        page = app.snapshots.page(snapshot_id, request.device_id, session_id, request.offset, request.limit)
        rows = page.pop('views')
        return {**page, 'instances': rows, 'session_id': session_id, 'reused': reused}

    app.tools.add('objc_query_instances', QueryInstances, query,
        'One-call allowlisted app instance values: reuse/attach, discover class instances or read mixed-class object_ids, '
        'then read bounded ivars without arbitrary getters/descriptions. Select field_names to minimize tokens; sensitive '
        'fields are redacted. Default first 8 ivars, 20 instances, 10 per page. snapshot_id pages never rescan the heap. '
        'Foundation strings/numbers/collections are bounded; other objects return leased references. ObjC-visible classes only.')
