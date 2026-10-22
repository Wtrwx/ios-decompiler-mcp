from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from vesper.app import Application
from vesper.config import StrictModel
from vesper.core.objc_types import header
from vesper.core.registry import new_id
from vesper.tools.models import ClassName, Identifier


class Dump(StrictModel):
    backend: Literal['auto', 'runtime', 'classdumpc'] = 'auto'
    device_id: Identifier | None = None
    bundle_id: Identifier | None = None
    binary_path: Path | None = None
    class_name: ClassName | None = None
    class_filter: str | None = Field(default=None, min_length=1, max_length=255)
    arch: Literal['arm64', 'arm64e', 'x86_64'] | None = None
    limit: int = Field(default=100, ge=1, le=500)
    preview_chars: int = Field(default=0, ge=0, le=8192)

    @model_validator(mode='after')
    def source(self) -> Dump:
        selected = 'classdumpc' if self.backend == 'auto' and self.binary_path else 'runtime' if self.backend == 'auto' else self.backend
        if selected == 'classdumpc':
            if self.binary_path is None or self.device_id or self.bundle_id:
                raise ValueError('classdumpc requires a local binary_path; omit device_id and bundle_id')
            if self.class_name and self.class_filter:
                raise ValueError('Choose class_name or class_filter')
        elif not (self.device_id and self.bundle_id and self.class_name) or self.binary_path or self.class_filter or self.arch:
            raise ValueError('runtime requires device_id, bundle_id and class_name; omit binary_path, class_filter and arch')
        self.backend = selected
        return self


def register(app: Application) -> None:
    async def dump(request: Dump) -> dict[str, Any]:
        if request.backend == 'classdumpc':
            assert request.binary_path is not None
            pattern = '^' + re.escape(request.class_name) + '$' if request.class_name else request.class_filter
            return await app.classdump.dump(request.binary_path, pattern, request.arch, request.preview_chars)
        assert request.device_id and request.bundle_id and request.class_name
        app.permissions.device(request.device_id, request.bundle_id)
        attached = await app.frida.attach(request.device_id, request.bundle_id)
        data = await app.frida.rpc(request.device_id, attached['session_id'], 'dump_class', {'class_name': request.class_name, 'offset': 0, 'limit': request.limit})
        text = header(data)
        directory = app.settings.state_dir / 'runtime-headers'
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / (request.class_name + '.h')
        # Atomic replacement keeps live metadata fresh without accumulating files.
        temporary = directory / new_id('header')
        with temporary.open('w', encoding='utf-8') as stream:
            temporary.chmod(0o600)
            stream.write(text)
        temporary.replace(path)
        result = {'backend': 'runtime', 'session_id': attached['session_id'], 'reused': attached.get('reused', False),
            'class_name': request.class_name, 'source': 'observed_runtime_metadata', 'local_path': str(path),
            'bytes': path.stat().st_size, 'truncated': data.get('methods', {}).get('next_offset') is not None}
        if request.preview_chars:
            result.update(preview=text[:request.preview_chars], preview_truncated=len(text) > request.preview_chars)
        return result

    app.tools.add('objc_dump', Dump, dump, 'Dump headers with automatic backend selection: local binary_path uses host classdumpc; device_id/bundle_id/class_name uses the live runtime and reuses its session. Returns a local header file; preview is opt-in and bounded. Static cache: 5 minutes, 4 files, 16 MiB. Use objc_query_instances for live values.')
