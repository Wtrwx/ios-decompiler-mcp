from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from vesper.app import Application
from vesper.config import StrictModel
from vesper.core.errors import Code, MCPError
from vesper.tools.models import Identifier

# Frequently needed primitives stay directly discoverable. Advanced tools remain
# callable through platform_tool, with their exact schema loaded only on demand.
FOCUSED_TOOLS = frozenset({
    'server_status', 'device_list', 'device_info', 'ui_capture', 'ui_snapshot',
    'ui_automate', 'objc_dump', 'objc_query_instances', 'app_logs', 'debug_inspect',
    'debug_setup', 'frida_trace_method', 'frida_get_events', 'frida_unhook',
    'frida_detach', 'job_status', 'job_cancel', 'platform_tool',
    'app_decrypt',
})


class Invoke(StrictModel):
    name: Identifier
    action: Literal['schema', 'call'] = 'call'
    arguments: dict[str, Any] = Field(default_factory=dict)


def register(app: Application) -> None:
    async def invoke(request: Invoke) -> dict[str, Any]:
        tool = app.tools.tools.get(request.name)
        if not tool or request.name == 'platform_tool':
            raise MCPError(Code.NOT_FOUND, 'Unknown platform primitive or recursive gateway call')
        if request.action == 'schema':
            return {'name': tool.name, 'description': tool.description, 'inputSchema': tool.model.model_json_schema()}
        result = await app.tools.invoke(request.name, request.arguments)
        if not result.ok:
            assert result.error is not None
            raise MCPError(Code(result.error.code), result.error.message,
                retryable=result.error.retryable, **result.error.details)
        return result.data or {}

    app.tools.add('platform_tool', Invoke, invoke, 'Access advanced Vesper primitives without loading the full catalog. action=schema returns one exact input schema; action=call validates and executes arguments. Names include objc_get_ivars, objc_get_methods, ui_inspect_view, tweak_*, ida_* and device_*. Existing operation checks apply. Use the vesper-ios skill for workflows.', read_only=False)
