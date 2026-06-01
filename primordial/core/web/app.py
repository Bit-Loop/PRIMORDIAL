from __future__ import annotations

from pathlib import Path
from threading import Lock, RLock
from typing import Any

from primordial.app.runtime import PrimordialRuntime
from primordial.core.web.context_views import WebContextViewsMixin
from primordial.core.web.integration_views import WebIntegrationViewsMixin
from primordial.core.web.request_helpers import WebRequestHelpersMixin
from primordial.core.web.responses import WebResponse
from primordial.core.web.routing import dispatch_web_request
from primordial.core.web.runtime_actions import WebRuntimeActionsMixin
from primordial.core.web.runtime_views import WebRuntimeViewsMixin
from primordial.core.web.scope_views import WebScopeViewsMixin
from primordial.core.web.task_views import WebTaskViewsMixin
from primordial.core.web.workspace_views import WebWorkspaceViewsMixin


class PrimordialWebApp(
    WebRuntimeActionsMixin,
    WebRequestHelpersMixin,
    WebRuntimeViewsMixin,
    WebTaskViewsMixin,
    WebScopeViewsMixin,
    WebContextViewsMixin,
    WebIntegrationViewsMixin,
    WebWorkspaceViewsMixin,
):
    STALE_WEB_ACTION_SECONDS = 900

    def __init__(self, runtime: PrimordialRuntime) -> None:
        self.runtime = runtime
        self._lock = RLock()
        self._tick_lock = Lock()
        self._actions_lock = RLock()
        self._active_actions: dict[str, dict[str, Any]] = {}
        self._static_dir = Path(__file__).resolve().parent / "static"

    def dispatch(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> WebResponse:
        return dispatch_web_request(self, method, raw_path, body, headers)
