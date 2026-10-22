from __future__ import annotations

import base64
import binascii
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import Field, model_validator

from vesper.app import Application
from vesper.config import StrictModel
from vesper.core.errors import Code, MCPError
from vesper.core.registry import new_id
from vesper.tools.models import (
    AppRequest,
    ClassName,
    Identifier,
    Page,
    SessionPage,
    SessionRequest,
)

ViewField = Literal['view_id', 'class_name', 'frame', 'screen_frame', 'parent_id', 'depth',
                    'interactive', 'accessibility_identifier', 'text', 'bounds', 'is_button',
                    'hidden', 'alpha', 'effective_alpha', 'visible', 'user_interaction_enabled',
                    'controller', 'targets', 'superview_id', 'subviews', 'translates_autoresizing_mask', 'observed']


class CaptureOptions(StrictModel):
    root_view_id: str | None = None
    depth: int = Field(default=8, ge=0, le=30)
    max_nodes: int = Field(default=1000, ge=1, le=2000)
    include_text: bool = False
    format: Literal['summary', 'detail'] = 'summary'
    fields: list[ViewField] | None = Field(default=None, max_length=25)
    visible_only: bool = True
    controls_only: bool = True


class Snapshot(SessionPage, CaptureOptions):
    snapshot_id: Identifier | None = None

    @model_validator(mode='after')
    def immutable_page(self) -> Snapshot:
        if self.snapshot_id and self.model_fields_set - {'snapshot_id', 'device_id', 'session_id', 'offset', 'limit'}:
            raise ValueError('A snapshot page only accepts snapshot_id, session_id, device_id, offset and limit; omit snapshot_id for a live capture')
        return self


class Capture(AppRequest, Page, CaptureOptions):
    mode: Literal['summary', 'screenshot', 'both']
    window_id: str | None = None


class View(SessionPage):
    view_id: str = Field(min_length=1, max_length=255)
    include_text: bool = False
    fields: list[ViewField] | None = Field(default=None, max_length=25)


class HitTest(SessionRequest):
    x: float = Field(allow_inf_nan=False)
    y: float = Field(allow_inf_nan=False)
    window_id: str | None = None
    include_text: bool = False


class FindViews(Snapshot):
    class_name: ClassName | None = None
    text: str | None = Field(default=None, max_length=512)
    accessibility_identifier: str | None = Field(default=None, max_length=255)
    hidden: bool | None = None
    user_interaction_enabled: bool | None = None
    visible_only: bool = False
    controls_only: bool = False


class Screenshot(SessionRequest):
    window_id: str | None = None


def save_screenshot(app: Application, result: dict[str, Any], rpc_ms: float) -> dict[str, Any]:
    started = time.perf_counter()
    png = result.get('_png')
    if png is None:
        encoded = result.get('base64', '')
        if not isinstance(encoded, str) or len(encoded) > 12 * 1024 * 1024:
            raise MCPError(Code.LIMIT_EXCEEDED, 'Screenshot exceeds the encoded size limit')
        try:
            png = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise MCPError(Code.FRIDA_ERROR, 'Screenshot agent returned invalid image data') from exc
    if not isinstance(png, bytes):
        raise MCPError(Code.FRIDA_ERROR, 'Screenshot agent returned invalid binary image data')
    if not png.startswith(b'\x89PNG\r\n\x1a\n') or len(png) > 8 * 1024 * 1024:
        raise MCPError(Code.FRIDA_ERROR, 'Screenshot is not a bounded PNG')
    directory = app.settings.state_dir / 'screenshots'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / (new_id('screenshot') + '.png')
    with path.open('xb') as output:
        path.chmod(0o600)
        output.write(png)
    return {'mime_type': 'image/png', 'local_path': str(path), 'bytes': len(png),
            **{key: result[key] for key in ('window_id', 'width_points', 'height_points', 'scale', 'frida_transport') if key in result},
            'timings_ms': {**result.get('timings_ms', {}), 'rpc_total': round(rpc_ms, 3),
                           'decode_and_save': round((time.perf_counter() - started) * 1000, 3)}, 'observed': True}


def register(app: Application) -> None:
    def rpc(method: str) -> Callable[[Any], Awaitable[dict[str, Any]]]:
        async def invoke(request: Any) -> dict[str, Any]:
            app.permissions.device(request.device_id)
            return await app.frida.rpc(request.device_id, request.session_id, method, request.model_dump(exclude={'device_id', 'session_id'}))
        return invoke

    def cache_page(snapshot_id: str, request: Any, data: dict[str, Any], started: float) -> dict[str, Any]:
        app.snapshots.store(snapshot_id, request.device_id, request.session_id, data, started)
        return app.snapshots.page(snapshot_id, request.device_id, request.session_id, request.offset, request.limit)

    def collect(method: str) -> Callable[[Any], Awaitable[dict[str, Any]]]:
        async def invoke(request: Snapshot) -> dict[str, Any]:
            app.permissions.device(request.device_id)
            if request.snapshot_id:
                app.frida.session(request.device_id, request.session_id)
                return app.snapshots.page(request.snapshot_id, request.device_id, request.session_id, request.offset, request.limit)
            snapshot_id, started = new_id('snapshot'), time.monotonic()
            args = request.model_dump(exclude={'device_id', 'session_id', 'snapshot_id', 'offset', 'limit'})
            try:
                data = await app.frida.rpc(request.device_id, request.session_id, method,
                    {**args, '_lease_id': snapshot_id, '_lease_ttl': app.settings.snapshot_ttl})
                return cache_page(snapshot_id, request, data, started)
            except BaseException:
                app.frida.release_lease(request.session_id, snapshot_id)
                raise
        return invoke

    async def screenshot(request: Screenshot) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        started = time.perf_counter()
        result = await app.frida.rpc(request.device_id, request.session_id, 'screenshot', {'window_id': request.window_id})
        saved = save_screenshot(app, result, (time.perf_counter() - started) * 1000)
        saved['timings_ms'].update(result.get('_agent_timings_ms', {}))
        return saved

    async def capture(request: Capture) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        for attempt in range(2):
            attached = await app.frida.attach(request.device_id, request.bundle_id)
            session_id = attached['session_id']
            lease_id, started = new_id('snapshot'), time.monotonic()
            try:
                result = await app.frida.rpc(request.device_id, session_id, 'capture',
                    {**request.model_dump(exclude={'device_id', 'bundle_id', 'offset', 'limit'}),
                     '_lease_id': lease_id, '_lease_ttl': app.settings.snapshot_ttl if request.mode != 'screenshot' else app.settings.object_handle_ttl})
                break
            except MCPError as exc:
                app.frida.release_lease(session_id, lease_id)
                if attempt or exc.code not in {Code.SESSION_INVALID, Code.FRIDA_ERROR}:
                    raise
        data: dict[str, Any] = {'session_id': session_id, 'device_id': request.device_id,
                                'bundle_id': request.bundle_id, 'reused': attached.get('reused', False)}
        try:
            if request.mode in {'summary', 'both'}:
                page_request = Snapshot(device_id=request.device_id, session_id=session_id, offset=request.offset, limit=request.limit)
                data['summary'] = cache_page(lease_id, page_request, result['summary'], started)
            if request.mode in {'screenshot', 'both'}:
                data['screenshot'] = save_screenshot(app, result['screenshot'], (time.monotonic() - started) * 1000)
                data['screenshot']['timings_ms'].update(result.get('_agent_timings_ms', {}))
            return data
        except BaseException:
            app.snapshots.discard(lease_id)
            app.frida.release_lease(session_id, lease_id)
            raise

    definitions: list[tuple[str, type[SessionRequest], str, str]] = [
        ('ui_get_windows', SessionRequest, 'windows', 'Enumerate UIWindow/UIScene state on the main thread.'),
        ('ui_inspect_view', View, 'inspect_view', 'Inspect a leased UIView, controller ownership, subviews and target-action mappings. Optional fields select expensive details.'),
        ('ui_get_constraints', View, 'constraints', "List this UIView's Auto Layout constraints with pagination."),
        ('ui_get_responder_chain', View, 'responders', 'Follow observed UIKit responders with a fixed depth cap.'),
        ('ui_hit_test', HitTest, 'hit_test', 'Hit-test UIKit window coordinates in points on the main thread.'),
    ]
    for name, model, operation, description in definitions:
        app.tools.add(name, model, rpc(operation), description)
    app.tools.add('ui_snapshot', Snapshot, collect('snapshot'), 'Capture a fresh bounded UIKit summary. Reuse snapshot_id + offset for immutable pages without device access. Text is opt-in; format=detail or fields selects extra metadata.')
    app.tools.add('ui_find_views', FindViews, collect('find_views'), 'Filter views on the device; reuse snapshot_id for immutable result pages. Text query/capture is explicit.')
    app.tools.add('ui_capture', Capture, capture, 'One-call allowlisted app capture with automatic session reuse/attach. Required mode=summary, screenshot or both; screenshots and text require explicit selection. Summary returns snapshot_id for paging.')
    app.tools.add('ui_screenshot', Screenshot, screenshot, 'Capture an explicitly requested bounded PNG as a local artifact and native MCP image when UIKit rendering is available.')
