from __future__ import annotations

import json

from primordial.app.runtime import PrimordialRuntime
from primordial.core.domain.enums import TaskStatus


def render_dashboard_text(runtime: PrimordialRuntime) -> str:
    snapshot = runtime.dashboard()
    scope = runtime.scope_payload()
    lines = ["Primordial Dashboard", "", "Counts:"]
    for key, value in sorted(snapshot.counts.items()):
        lines.append(f"  {key}: {value}")

    lines.extend(["", "Sessions:"])
    for session in snapshot.sessions[:4]:
        lines.append(
            f"  {session.status.value:10} {session.methodology.value:16} "
            f"profile={session.profile.value} autonomy={session.autonomy_mode}"
        )

    lines.extend(["", "Targets:"])
    for target_entry in scope["targets"][:8]:
        target = target_entry["target"]
        assets = target_entry["assets"]
        counts = target_entry["counts"]
        lines.append(
            f"  {target['display_name']} [{target['profile']}] in_scope={target['in_scope']} "
            f"assets={counts['assets']} tasks={counts['tasks']} evidence={counts['evidence']}"
        )
        for asset in assets[:4]:
            lines.append(f"    - {asset['asset_type']}: {asset['asset']}")

    lines.extend(["", "Tasks:"])
    for task in snapshot.tasks[:10]:
        route = task.provider_route.value if task.provider_route else "-"
        model = task.provider_model or "-"
        lines.append(
            f"  {task.status.value:16} {task.kind.value:24} {route:14} {model:18} {task.title}"
        )

    lines.extend(["", "Recent Runs:"])
    for run in snapshot.task_runs[:8]:
        lines.append(
            f"  {run.status.value:10} {run.provider_route.value:14} model={run.model_name:18} task={run.task_id}"
        )

    lines.extend(["", "Notifications:"])
    for notification in snapshot.notifications[:6]:
        lines.append(
            f"  {notification.status.value:10} {notification.channel.value:8} {notification.summary}"
        )

    lines.extend(["", "Sync Jobs:"])
    for job in snapshot.sync_jobs[:6]:
        lines.append(
            f"  {job.status.value:10} {job.kind.value:8} target={job.target_id} {job.summary}"
        )

    lines.extend(["", "Recent Events:"])
    for event in snapshot.events[:10]:
        lines.append(f"  {event.type.value:22} {event.summary}")
    return "\n".join(lines)


def render_scope_text(runtime: PrimordialRuntime, *, as_json: bool = False) -> str:
    scope = runtime.scope_payload()
    if as_json:
        return json.dumps(scope, indent=2, sort_keys=True)
    lines = [
        "Primordial Scope",
        "",
        f"Targets: {scope['totals']['targets']}",
        f"In Scope: {scope['totals']['in_scope']}",
        f"Assets: {scope['totals']['assets']}",
        "",
    ]
    for target_entry in scope["targets"]:
        target = target_entry["target"]
        counts = target_entry["counts"]
        lines.append(
            f"{target['display_name']} [{target['profile']}] handle={target['handle']} in_scope={target['in_scope']}"
        )
        lines.append(
            f"  assets={counts['assets']} tasks={counts['tasks']} evidence={counts['evidence']} "
            f"notes={counts['notes']} interests={counts['interests']} findings={counts['findings']}"
        )
        for asset in target_entry["assets"]:
            lines.append(f"  - {asset['asset_type']}: {asset['asset']}")
        lines.append("")
    return "\n".join(lines).rstrip()


def launch_tui(runtime: PrimordialRuntime) -> int:
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal
        from textual.widgets import DataTable, Footer, Header, Static
    except ImportError:
        print(render_dashboard_text(runtime))
        return 0

    class PrimordialTextualApp(App[None]):
        CSS = """
        Screen {
            layout: vertical;
        }
        #body {
            layout: horizontal;
            height: 1fr;
        }
        DataTable {
            width: 55%;
        }
        #summary {
            width: 45%;
            padding: 1 2;
            border: round $surface;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
            ("t", "tick", "Run Tick"),
            ("m", "compact", "Compact Memory"),
            ("p", "process", "Process Queues"),
            ("a", "approve_first", "Approve First"),
        ]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="body"):
                yield DataTable(id="tasks")
                yield Static(id="summary")
            yield Footer()

        def on_mount(self) -> None:
            tasks = self.query_one("#tasks", DataTable)
            tasks.add_columns("Status", "Kind", "Route", "Model", "Title")
            self._refresh_views()

        def action_refresh(self) -> None:
            self._refresh_views()

        def action_tick(self) -> None:
            runtime.run_tick()
            self._refresh_views()

        def action_compact(self) -> None:
            runtime.compact_memory()
            self._refresh_views()

        def action_process(self) -> None:
            runtime.process_external_queues()
            self._refresh_views()

        def action_approve_first(self) -> None:
            for task in runtime.dashboard().tasks:
                if task.status == TaskStatus.NEEDS_APPROVAL:
                    runtime.approve_task(task.id, approved=True)
                    break
            self._refresh_views()

        def _refresh_views(self) -> None:
            snapshot = runtime.dashboard()
            tasks = self.query_one("#tasks", DataTable)
            tasks.clear()
            for task in snapshot.tasks[:20]:
                tasks.add_row(
                    task.status.value,
                    task.kind.value,
                    task.provider_route.value if task.provider_route else "-",
                    task.provider_model or "-",
                    task.title,
                )
            summary = self.query_one("#summary", Static)
            summary.update(render_dashboard_text(runtime))

    PrimordialTextualApp().run()
    return 0
