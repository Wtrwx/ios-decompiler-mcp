from __future__ import annotations

import time
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from vesper.app import Application
from vesper.config import StrictModel
from vesper.core.registry import new_id
from vesper.tools.models import AppRequest, ClassName
from vesper.tools.ui import CaptureOptions, save_screenshot


class Target(StrictModel):
    view_id: str | None = Field(default=None, max_length=255)
    accessibility_identifier: str | None = Field(default=None, max_length=255)
    class_name: ClassName | None = None
    text: str | None = Field(default=None, max_length=512)
    x: float | None = Field(default=None, allow_inf_nan=False)
    y: float | None = Field(default=None, allow_inf_nan=False)
    window_id: str | None = Field(default=None, max_length=255)
    match_index: int | None = Field(default=None, ge=0, le=99)

    @model_validator(mode='after')
    def select_target(self) -> Target:
        if (self.x is None) != (self.y is None):
            raise ValueError('x and y must be supplied together in window UIKit points')
        selector = self.accessibility_identifier is not None or self.class_name is not None or self.text is not None
        if int(self.view_id is not None) + int(self.x is not None) + int(selector) != 1:
            raise ValueError('Choose view_id, x+y, or a selector; do not mix target forms')
        return self


class TargetStep(StrictModel):
    target: Target


class Tap(TargetStep):
    action: Literal['tap']
    event: Literal['auto', 'touch_up_inside', 'primary_action'] = 'auto'


class Back(StrictModel):
    action: Literal['back']
    mode: Literal['auto', 'navigation', 'dismiss'] = 'auto'
    window_id: str | None = Field(default=None, max_length=255)
    animated: bool = False


class InputText(TargetStep):
    action: Literal['input_text']
    text: str = Field(max_length=4096)
    focus: bool = False


class Scroll(TargetStep):
    action: Literal['scroll']
    dx: float = Field(default=0, ge=-10000, le=10000, allow_inf_nan=False)
    dy: float = Field(default=0, ge=-10000, le=10000, allow_inf_nan=False)
    pages: int | None = Field(default=None, ge=-10, le=10,
                              description='Vertical viewport pages: 1 advances, -1 goes back. Exclusive with dx/dy.')
    animated: bool = False

    @model_validator(mode='after')
    def select_distance(self) -> Scroll:
        if self.pages is not None and (self.pages == 0 or self.dx != 0 or self.dy != 0):
            raise ValueError('pages must be nonzero and cannot be combined with dx/dy')
        return self


class Assert(TargetStep):
    action: Literal['assert']


class WaitFor(TargetStep):
    action: Literal['wait_for']
    timeout_ms: int = Field(default=1000, ge=0, le=5000)
    poll_ms: int = Field(default=100, ge=50, le=1000)


Step = Annotated[Tap | Back | InputText | Scroll | Assert | WaitFor, Field(discriminator='action')]


class Automate(AppRequest, CaptureOptions):
    steps: list[Step] = Field(min_length=1, max_length=20)
    after_capture: Literal['none', 'summary', 'screenshot', 'both'] = 'none'
    settle_ms: int = Field(default=0, ge=0, le=500)
    limit: int = Field(default=20, ge=1, le=100)

    @model_validator(mode='after')
    def bounded_wait(self) -> Automate:
        if sum(s.timeout_ms for s in self.steps if isinstance(s, WaitFor)) + self.settle_ms * len(self.steps) > 10000:
            raise ValueError('Total configured waiting must not exceed 10000ms')
        return self


def register(app: Application) -> None:
    async def automate(request: Automate) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        attached = await app.frida.attach(request.device_id, request.bundle_id)
        session_id, lease_id = attached['session_id'], new_id('snapshot')
        arguments = request.model_dump(exclude={'device_id', 'bundle_id', 'limit'})
        # Mutations are never automatically retried: a timeout can have an
        # uncertain outcome, even when the Frida session is subsequently lost.
        started = time.monotonic()
        try:
            result = await app.frida.rpc(request.device_id, session_id, 'automate', {**arguments,
                '_lease_id': lease_id, '_lease_ttl': app.settings.snapshot_ttl if request.after_capture in {'summary', 'both'} else app.settings.object_handle_ttl})
            data = {'session_id': session_id, 'reused': attached.get('reused', False),
                    **{key: result[key] for key in ('steps', 'completed', 'elapsed_ms')}}
            if 'summary' in result:
                app.snapshots.store(lease_id, request.device_id, session_id, result['summary'], started)
                data['summary'] = app.snapshots.page(lease_id, request.device_id, session_id, 0, request.limit)
            if 'screenshot' in result:
                data['screenshot'] = save_screenshot(app, result['screenshot'], (time.monotonic() - started) * 1000)
            return data
        except BaseException:
            app.snapshots.discard(lease_id)
            app.frida.release_lease(session_id, lease_id)
            raise

    app.tools.add('ui_automate', Automate, automate,
        'Run an app-scoped batch: tap, back/dismiss, input_text, scroll, assert or bounded wait_for. '
        'Uses UIKit control/accessibility actions, not physical touch injection. Select targets by leased view_id, '
        'identifier/class/text or window x+y. No implicit wait/screenshots/text. Optional after_capture reuses the same RPC. '
        'Stops at the first failure; never automatically retries mutations.', read_only=False)
