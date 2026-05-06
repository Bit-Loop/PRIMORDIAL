from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from threading import Event, RLock, Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from primordial.app.runtime import PrimordialRuntime
from primordial.core.domain.enums import MethodologyName, ScopeProfile
from primordial.core.web import WebConsoleThread
from primordial.ui.textual_app import render_dashboard_text


SOLARIZED = {
    "base03": "#002b36",
    "base02": "#073642",
    "base01": "#586e75",
    "base00": "#657b83",
    "base0": "#839496",
    "base1": "#93a1a1",
    "base2": "#eee8d5",
    "yellow": "#b58900",
    "orange": "#cb4b16",
    "red": "#dc322f",
    "magenta": "#d33682",
    "violet": "#6c71c4",
    "blue": "#268bd2",
    "cyan": "#2aa198",
    "green": "#859900",
}


def launcher_target_state(runtime: PrimordialRuntime, preferred_handle: str = "pirate.htb") -> dict[str, object]:
    """Return persisted target state the launcher should display on startup."""
    targets = runtime.store.list_targets()
    if not targets:
        return {}
    target = runtime.store.get_target_by_handle(preferred_handle) or next(
        (item for item in sorted(targets, key=lambda value: value.updated_at, reverse=True) if item.profile == ScopeProfile.HACK_THE_BOX),
        sorted(targets, key=lambda value: value.updated_at, reverse=True)[0],
    )
    assets = runtime.store.list_scope_assets(target.id)
    active_generation = (
        str(target.metadata["active_ip_generation"])
        if target.metadata.get("active_ip_generation") is not None
        else None
    )
    active_ip = str(target.metadata.get("active_ip") or "").strip()
    if not active_ip:
        active_ip = next((asset.asset for asset in assets if asset.asset_type == "ip"), "")
    evidence = runtime.store.list_evidence(target_id=target.id, limit=500)
    stale_evidence_count = 0
    if active_generation is not None:
        stale_evidence_count = sum(
            1
            for item in evidence
            if str(item.metadata.get("active_ip_generation", "")) != active_generation
        )
    return {
        "target": target,
        "handle": target.handle,
        "display_name": target.display_name,
        "profile": target.profile.value,
        "assets": [asset.asset for asset in assets],
        "active_ip": active_ip,
        "active_ip_generation": active_generation,
        "stale_evidence_count": stale_evidence_count,
    }


class PrimordialLauncher:
    def __init__(self, runtime: PrimordialRuntime) -> None:
        self.runtime = runtime
        self.root = tk.Tk()
        self.root.title("Primordial Launcher")
        self.root.geometry("920x680")
        self._style = ttk.Style()
        self._configure_solarized_dark_theme()
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.IntVar(value=1337)
        # scope_handle_var / scope_active_ip_var are canonical; target_var / ip_var are aliases
        self.scope_handle_var = tk.StringVar(value="pirate.htb")
        self.target_var = self.scope_handle_var
        self.scope_active_ip_var = tk.StringVar(value="10.129.47.117")
        self.ip_var = self.scope_active_ip_var
        self.title_var = tk.StringVar(value="HTB Pirate Session")
        self.scope_display_name_var = tk.StringVar(value="HTB Pirate")
        self.scope_profile_var = tk.StringVar(value=ScopeProfile.HACK_THE_BOX.value)
        self.scope_assets_var = tk.StringVar(value="")
        self.scope_in_scope_var = tk.BooleanVar(value=True)
        self.scope_profile_id_var = tk.StringVar()
        self.scope_profile_label_var = tk.StringVar()
        self.scope_profile_base_var = tk.StringVar(value=ScopeProfile.HACK_THE_BOX.value)
        self.scope_profile_description_var = tk.StringVar()
        self.guidance_target_var = tk.StringVar(value="pirate.htb")
        self.cycles_var = tk.IntVar(value=10)
        self.max_executions_var = tk.IntVar(value=3)
        self.web_status_var = tk.StringVar(value="Web server: stopped")
        self.work_status_var = tk.StringVar(value="Work status: idle")
        self.current_work_summary_var = tk.StringVar(value="Current work: idle")
        self.cpu_load_var = tk.StringVar(value="CPU: sampling")
        self.gpu_load_var = tk.StringVar(value="GPU: sampling")
        self.runtime_tuning_status_var = tk.StringVar(value="Runtime tuning: defaults")
        self.target_persistence_status_var = tk.StringVar(value="Active target: not loaded")
        self.scope_status_var = tk.StringVar(value="")
        self.htb_ip_warning_var = self.scope_status_var
        self.scope_ip_warning_var = self.scope_status_var
        self.scope_assets_tree: ttk.Treeview | None = None
        self._scope_asset_rows: list[dict] = []
        self.execution_mode_var = tk.StringVar(value="tick")
        self.execution_toggle_text_var = tk.StringVar(value="Enable Continuous Mode")
        self.execution_mode_status_var = tk.StringVar(value="Execution mode: tick")
        self.continuous_interval_var = tk.IntVar(value=PrimordialRuntime.DEFAULT_EXECUTION_INTERVAL_SECONDS)
        self.gpu_ai_timeout_var = tk.IntVar(value=PrimordialRuntime.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU)
        self.cpu_ai_timeout_var = tk.IntVar(value=PrimordialRuntime.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU)
        self.stale_run_timeout_var = tk.IntVar(value=PrimordialRuntime.DEFAULT_STALE_RUN_TIMEOUT_SECONDS)
        self.model_vars: dict[str, tk.StringVar] = {}
        self.model_processor_vars: dict[str, tk.StringVar] = {}
        self.model_combos: dict[str, ttk.Combobox] = {}
        self.model_processor_combos: dict[str, ttk.Combobox] = {}
        self.run_more_ticks_button: ttk.Button | None = None
        self.stop_work_button: ttk.Button | None = None
        self.continuous_interval_entry: ttk.Entry | None = None
        self.gpu_ai_timeout_entry: ttk.Entry | None = None
        self.cpu_ai_timeout_entry: ttk.Entry | None = None
        self.stale_run_timeout_entry: ttk.Entry | None = None
        self.scope_profile_combo: ttk.Combobox | None = None
        self.scope_profiles_tree: ttk.Treeview | None = None
        self.cpu_progress: ttk.Progressbar | None = None
        self.gpu_progress: ttk.Progressbar | None = None
        self.chat_target_var = tk.StringVar(value="pirate.htb")
        self.notion_api_key_var = tk.StringVar()
        self.notion_parent_page_id_var = tk.StringVar()
        self.notion_version_var = tk.StringVar(value="2022-06-28")
        self.discord_webhook_var = tk.StringVar()
        self.lab_username_var = tk.StringVar()
        self.lab_password_var = tk.StringVar()
        self.lab_domain_var = tk.StringVar()
        self.caido_graphql_url_var = tk.StringVar(value="http://127.0.0.1:8080/graphql")
        self.caido_api_token_var = tk.StringVar()
        self.credentials_status_var = tk.StringVar(value="Credentials: not loaded")
        self.ai_thinking_auto_var = tk.BooleanVar(value=True)
        self.ai_thinking_interval_var = tk.IntVar(value=5)
        self._ai_thinking_clear_after: datetime | None = None
        self.agent_monitor_auto_var = tk.BooleanVar(value=True)
        self.agent_monitor_interval_var = tk.IntVar(value=5)
        self._agent_monitor_clear_after: datetime | None = None
        self._closed = False
        self._web_server: WebConsoleThread | None = None
        self._queue: Queue[tuple[str, object]] = Queue()
        self._runtime_lock = RLock()
        self._stop_requested = Event()
        self._continuous_tick_running = False
        self._system_status_refresh_running = False
        self._agent_monitor_refresh_running = False
        self._ai_thinking_refresh_running = False
        self._chat_refresh_running = False
        self._applied_execution_interval_seconds = PrimordialRuntime.DEFAULT_EXECUTION_INTERVAL_SECONDS
        self._execution_mode_after_id: str | None = None
        self._operation_seq = 0
        self._active_operations: dict[str, dict[str, str]] = {}
        self.root.report_callback_exception = self._handle_tk_exception
        self._build_ui()
        self._hydrate_target_fields_from_store()
        self._install_target_warning_traces()
        self._poll_queue()
        self._poll_current_work()
        self._poll_agent_monitor()
        self._poll_ai_thinking()
        self._poll_execution_mode()
        self._poll_system_metrics()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_solarized_dark_theme(self) -> None:
        palette = SOLARIZED
        try:
            self._style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(background=palette["base03"])
        self.root.option_add("*background", palette["base03"])
        self.root.option_add("*foreground", palette["base0"])
        self.root.option_add("*insertBackground", palette["base1"])
        self.root.option_add("*selectBackground", palette["blue"])
        self.root.option_add("*selectForeground", palette["base03"])

        self._style.configure(
            ".",
            background=palette["base03"],
            foreground=palette["base0"],
            fieldbackground=palette["base02"],
            bordercolor=palette["base01"],
            darkcolor=palette["base03"],
            lightcolor=palette["base02"],
            troughcolor=palette["base02"],
            focuscolor=palette["blue"],
        )
        self._style.configure("TFrame", background=palette["base03"])
        self._style.configure("TLabel", background=palette["base03"], foreground=palette["base0"])
        self._style.configure("TCheckbutton", background=palette["base03"], foreground=palette["base0"])
        self._style.map("TCheckbutton", background=[("active", palette["base02"])], foreground=[("active", palette["base1"])])
        self._style.configure("TLabelframe", background=palette["base03"], bordercolor=palette["base01"])
        self._style.configure(
            "TLabelframe.Label",
            background=palette["base03"],
            foreground=palette["yellow"],
            font=("TkDefaultFont", 10, "bold"),
        )
        self._style.configure("TNotebook", background=palette["base03"], borderwidth=0)
        self._style.configure(
            "TNotebook.Tab",
            background=palette["base02"],
            foreground=palette["base0"],
            padding=(12, 6),
        )
        self._style.map(
            "TNotebook.Tab",
            background=[("selected", palette["base03"]), ("active", palette["base01"])],
            foreground=[("selected", palette["cyan"]), ("active", palette["base2"])],
        )
        self._style.configure(
            "TButton",
            background=palette["base02"],
            foreground=palette["base1"],
            bordercolor=palette["base01"],
            focusthickness=1,
            padding=(8, 4),
        )
        self._style.map(
            "TButton",
            background=[("disabled", palette["base03"]), ("pressed", palette["base01"]), ("active", palette["base01"])],
            foreground=[("disabled", palette["base00"]), ("active", palette["base2"])],
        )
        self._style.configure("Muted.TButton", background=palette["base03"], foreground=palette["base00"])
        self._style.map("Muted.TButton", foreground=[("disabled", palette["base00"])])
        self._style.configure(
            "TEntry",
            fieldbackground=palette["base02"],
            foreground=palette["base1"],
            insertcolor=palette["base1"],
            bordercolor=palette["base01"],
        )
        self._style.configure(
            "TCombobox",
            fieldbackground=palette["base02"],
            background=palette["base02"],
            foreground=palette["base1"],
            arrowcolor=palette["cyan"],
            bordercolor=palette["base01"],
        )
        self._style.map(
            "TCombobox",
            fieldbackground=[("readonly", palette["base02"])],
            foreground=[("readonly", palette["base1"])],
            selectbackground=[("readonly", palette["base02"])],
            selectforeground=[("readonly", palette["base1"])],
        )
        self._style.configure(
            "Treeview",
            background=palette["base02"],
            fieldbackground=palette["base02"],
            foreground=palette["base0"],
            bordercolor=palette["base01"],
            rowheight=24,
        )
        self._style.configure(
            "Treeview.Heading",
            background=palette["base03"],
            foreground=palette["yellow"],
            bordercolor=palette["base01"],
            font=("TkDefaultFont", 10, "bold"),
        )
        self._style.map(
            "Treeview",
            background=[("selected", palette["blue"])],
            foreground=[("selected", palette["base03"])],
        )
        self._style.configure(
            "Cpu.Horizontal.TProgressbar",
            troughcolor=palette["base02"],
            background=palette["blue"],
            bordercolor=palette["base01"],
            lightcolor=palette["cyan"],
            darkcolor=palette["blue"],
        )
        self._style.configure(
            "Gpu.Horizontal.TProgressbar",
            troughcolor=palette["base02"],
            background=palette["orange"],
            bordercolor=palette["base01"],
            lightcolor=palette["yellow"],
            darkcolor=palette["orange"],
        )

    def _configure_text_widget(self, widget: tk.Text) -> None:
        palette = SOLARIZED
        widget.configure(
            background=palette["base02"],
            foreground=palette["base0"],
            insertbackground=palette["base1"],
            selectbackground=palette["blue"],
            selectforeground=palette["base03"],
            highlightbackground=palette["base01"],
            highlightcolor=palette["blue"],
            relief=tk.FLAT,
            borderwidth=1,
            padx=8,
            pady=6,
        )

    def run(self) -> int:
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._close()
            return 130
        return 0

    def _build_ui(self) -> None:
        root = ttk.Frame(self.root, padding=12)
        root.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(root)
        header.pack(fill=tk.X)
        ttk.Label(header, text="Primordial Local Launcher", font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        status_stack = ttk.Frame(header)
        status_stack.pack(side=tk.RIGHT, fill=tk.X)
        ttk.Label(status_stack, textvariable=self.web_status_var).pack(anchor=tk.E)
        monitors = ttk.Frame(status_stack)
        monitors.pack(anchor=tk.E, pady=(6, 0))
        cpu_frame = ttk.Frame(monitors)
        cpu_frame.pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(cpu_frame, textvariable=self.cpu_load_var).pack(anchor=tk.W)
        self.cpu_progress = ttk.Progressbar(
            cpu_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
            length=180,
            maximum=100,
            style="Cpu.Horizontal.TProgressbar",
        )
        self.cpu_progress.pack(fill=tk.X, expand=True)
        gpu_frame = ttk.Frame(monitors)
        gpu_frame.pack(side=tk.LEFT)
        ttk.Label(gpu_frame, textvariable=self.gpu_load_var).pack(anchor=tk.W)
        self.gpu_progress = ttk.Progressbar(
            gpu_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
            length=180,
            maximum=100,
            style="Gpu.Horizontal.TProgressbar",
        )
        self.gpu_progress.pack(fill=tk.X, expand=True)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(12, 0))

        main_tab = ttk.Frame(self.notebook, padding=8)
        monitor_tab = ttk.Frame(self.notebook, padding=8)
        thinking_tab = ttk.Frame(self.notebook, padding=8)
        chat_tab = ttk.Frame(self.notebook, padding=8)
        counts_tab = ttk.Frame(self.notebook, padding=8)
        config_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(main_tab, text="Main")
        self.notebook.add(monitor_tab, text="Agent Monitor")
        self.notebook.add(thinking_tab, text="AI Thinking")
        self.notebook.add(chat_tab, text="Operator Chat")
        self.notebook.add(counts_tab, text="Counts")
        self.notebook.add(config_tab, text="Config")

        self._build_main_tab(main_tab)
        self._build_monitor_tab(monitor_tab)
        self._build_ai_thinking_tab(thinking_tab)
        self._build_chat_tab(chat_tab)
        self._build_counts_tab(counts_tab)
        self._build_config_tab(config_tab)
        self._write_output("Launcher ready. Start the web server, then press Start Pirate Work.\n")
        self._refresh_all_tabs()
        self._refresh_target_ip_warnings()

    def _build_main_tab(self, root: ttk.Frame) -> None:
        server_frame = ttk.LabelFrame(root, text="Web Console", padding=10)
        server_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(server_frame, text="Host").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(server_frame, textvariable=self.host_var, width=18).grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(server_frame, text="Port").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(server_frame, textvariable=self.port_var, width=8).grid(row=0, column=3, sticky=tk.W, padx=6)
        ttk.Button(server_frame, text="Start Web Server", command=self._start_web_server).grid(row=0, column=4, padx=6)
        ttk.Button(server_frame, text="Open Browser", command=self._open_browser).grid(row=0, column=5, padx=6)
        ttk.Button(server_frame, text="Stop Web Server", command=self._stop_web_server).grid(row=0, column=6, padx=6)

        self._build_scope_target_frame(root)

        notes_frame = ttk.LabelFrame(root, text="Tips, Program Notes, and Agent Guidance", padding=10)
        notes_frame.pack(fill=tk.X, pady=8)
        tips = (
            "Tips: use tick mode for controlled work, continuous mode for bounded autonomous loops, "
            "keep target scope explicit, and place durable agent instructions in guidance instead of chat."
        )
        ttk.Label(notes_frame, text=tips, wraplength=840, justify=tk.LEFT).grid(row=0, column=0, columnspan=4, sticky=tk.W)
        ttk.Label(notes_frame, text="Guidance target").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Entry(notes_frame, textvariable=self.guidance_target_var, width=28).grid(row=1, column=1, sticky=tk.W, padx=6, pady=(8, 0))
        ttk.Button(notes_frame, text="Load Guidance", command=self._load_guidance).grid(row=1, column=2, padx=6, pady=(8, 0))
        ttk.Button(notes_frame, text="Save Guidance", command=self._save_guidance).grid(row=1, column=3, padx=6, pady=(8, 0))
        self.guidance_input = tk.Text(notes_frame, wrap=tk.WORD, height=5)
        self._configure_text_widget(self.guidance_input)
        self.guidance_input.grid(row=2, column=0, columnspan=4, sticky=tk.EW, pady=(8, 0))
        notes_frame.columnconfigure(1, weight=1)

        action_frame = ttk.LabelFrame(root, text="One-Click Workflow", padding=10)
        action_frame.pack(fill=tk.X, pady=8)
        ttk.Label(action_frame, text="Cycles").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(action_frame, textvariable=self.cycles_var, width=8).grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(action_frame, text="Max executions/tick").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(action_frame, textvariable=self.max_executions_var, width=8).grid(row=0, column=3, sticky=tk.W, padx=6)
        ttk.Button(action_frame, text="Warm Models", command=lambda: self._run_background("Warming models", self._warm_models)).grid(row=0, column=4, padx=6)
        ttk.Button(action_frame, text="Start Pirate Work", command=self._start_pirate_work).grid(row=0, column=5, padx=6)
        self.run_more_ticks_button = ttk.Button(action_frame, text="Run More Ticks", command=self._run_more_ticks)
        self.run_more_ticks_button.grid(row=0, column=6, padx=6)
        self.stop_work_button = ttk.Button(action_frame, text="Stop Work", command=self._stop_work)
        self.stop_work_button.grid(row=0, column=7, padx=6)
        ttk.Button(action_frame, text="Clear Models", command=lambda: self._run_background("Clearing models", self._clear_models)).grid(row=0, column=8, padx=6)
        ttk.Button(action_frame, text="Check System", command=self._check_system).grid(row=0, column=9, padx=6)
        ttk.Button(action_frame, text="Exit", command=self._close).grid(row=0, column=10, padx=6)
        ttk.Label(action_frame, textvariable=self.work_status_var).grid(row=1, column=0, columnspan=10, sticky=tk.W, pady=(8, 0))
        ttk.Label(action_frame, textvariable=self.execution_mode_status_var).grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(8, 0))
        ttk.Label(action_frame, text="Tick interval seconds").grid(row=2, column=3, sticky=tk.W, pady=(8, 0))
        self.continuous_interval_entry = ttk.Entry(action_frame, textvariable=self.continuous_interval_var, width=8)
        self.continuous_interval_entry.grid(row=2, column=4, sticky=tk.W, padx=6, pady=(8, 0))
        ttk.Button(action_frame, text="Apply Tick Interval", command=self._apply_tick_interval).grid(
            row=2, column=5, sticky=tk.W, padx=6, pady=(8, 0)
        )
        ttk.Button(action_frame, textvariable=self.execution_toggle_text_var, command=self._toggle_execution_mode).grid(
            row=2, column=6, columnspan=2, sticky=tk.W, padx=6, pady=(8, 0)
        )

        current_frame = ttk.LabelFrame(root, text="Current Work", padding=10)
        current_frame.pack(fill=tk.X, pady=8)
        ttk.Label(current_frame, textvariable=self.current_work_summary_var).pack(anchor=tk.W)
        self.current_work_output = tk.Text(current_frame, wrap=tk.WORD, height=7)
        self._configure_text_widget(self.current_work_output)
        self.current_work_output.pack(fill=tk.X, expand=False, pady=(8, 0))
        self.current_work_output.configure(state=tk.DISABLED)

        self.output = tk.Text(root, wrap=tk.WORD, height=22)
        self._configure_text_widget(self.output)
        self.output.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        footer = ttk.Frame(root)
        footer.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(footer, text="Refresh Status", command=self._refresh_status).pack(side=tk.LEFT)
        ttk.Button(footer, text="Ask: status and next step", command=self._ask_status).pack(side=tk.LEFT, padx=6)
        ttk.Button(footer, text="Refresh All Tabs", command=self._request_refresh_all_tabs).pack(side=tk.LEFT, padx=6)

    def _build_monitor_tab(self, root: ttk.Frame) -> None:
        controls = ttk.Frame(root)
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="Task runs · traces · events · status. AI reasoning text is in AI Thinking.").pack(side=tk.LEFT)
        ttk.Button(controls, text="Refresh Now", command=self._trigger_agent_monitor_refresh).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(controls, text="Clear Screen", command=self._clear_agent_monitor_screen).pack(side=tk.RIGHT)
        ttk.Checkbutton(controls, text="Auto", variable=self.agent_monitor_auto_var).pack(side=tk.RIGHT, padx=(12, 4))
        ttk.Label(controls, text="Interval s").pack(side=tk.RIGHT)
        ttk.Entry(controls, textvariable=self.agent_monitor_interval_var, width=5).pack(side=tk.RIGHT, padx=4)
        self.agent_output = tk.Text(root, wrap=tk.WORD, height=34)
        self._configure_text_widget(self.agent_output)
        self._configure_monitor_tags()
        self.agent_output.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.agent_output.configure(state=tk.DISABLED)

    def _build_ai_thinking_tab(self, root: ttk.Frame) -> None:
        controls = ttk.Frame(root)
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="AI-generated text only — color coded by agent role. Clear Screen keeps DB records.").pack(side=tk.LEFT)
        ttk.Checkbutton(controls, text="Auto", variable=self.ai_thinking_auto_var).pack(side=tk.LEFT, padx=(12, 4))
        ttk.Label(controls, text="Interval s").pack(side=tk.LEFT)
        ttk.Entry(controls, textvariable=self.ai_thinking_interval_var, width=5).pack(side=tk.LEFT, padx=4)
        ttk.Button(controls, text="Refresh Now", command=self._trigger_ai_thinking_refresh).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(controls, text="Clear Screen", command=self._clear_ai_thinking_screen).pack(side=tk.RIGHT)
        self.ai_thinking_output = tk.Text(root, wrap=tk.WORD, height=34)
        self._configure_text_widget(self.ai_thinking_output)
        self.ai_thinking_output.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self._configure_ai_thinking_tags()
        self.ai_thinking_output.configure(state=tk.DISABLED)

    def _configure_ai_thinking_tags(self) -> None:
        role_colors = {
            "recon_worker": (SOLARIZED["cyan"], SOLARIZED["base02"]),
            "analysis_worker": (SOLARIZED["blue"], SOLARIZED["base02"]),
            "code_worker": (SOLARIZED["green"], SOLARIZED["base02"]),
            "memory_worker": (SOLARIZED["violet"], SOLARIZED["base02"]),
            "behavior_verifier": (SOLARIZED["yellow"], SOLARIZED["base02"]),
            "chaining_worker": (SOLARIZED["magenta"], SOLARIZED["base02"]),
            "claude_reviewer": (SOLARIZED["orange"], SOLARIZED["base02"]),
            "Primordial AI": (SOLARIZED["base1"], SOLARIZED["base02"]),
            "unknown-agent": (SOLARIZED["base0"], SOLARIZED["base02"]),
        }
        for role, (foreground, background) in role_colors.items():
            tag = self._ai_role_tag(role)
            self.ai_thinking_output.tag_configure(
                tag,
                foreground=foreground,
                background=background,
                lmargin1=8,
                lmargin2=8,
                spacing1=2,
                spacing3=2,
            )
            self.ai_thinking_output.tag_configure(
                f"{tag}_speaker",
                foreground=foreground,
                background=background,
                font=("TkDefaultFont", 10, "bold"),
            )
        self.ai_thinking_output.tag_configure(
            "ai_section_head",
            foreground=SOLARIZED["yellow"],
            background=SOLARIZED["base03"],
            font=("TkDefaultFont", 10, "bold"),
        )
        self.ai_thinking_output.tag_configure(
            "ai_dim",
            foreground=SOLARIZED["base00"],
            background=SOLARIZED["base02"],
        )

    def _configure_monitor_tags(self) -> None:
        palette = SOLARIZED
        # Status badge colors for task/run states
        status_colors = {
            "running":       (palette["green"],   palette["base02"]),
            "succeeded":     (palette["cyan"],    palette["base02"]),
            "failed":        (palette["red"],     palette["base02"]),
            "timed_out":     (palette["orange"],  palette["base02"]),
            "pending":       (palette["base1"],   palette["base02"]),
            "needs_approval":(palette["yellow"],  palette["base02"]),
            "cancelled":     (palette["base01"],  palette["base02"]),
            "section_head":  (palette["yellow"],  palette["base03"]),
        }
        for name, (fg, bg) in status_colors.items():
            self.agent_output.tag_configure(
                f"mon_{name}",
                foreground=fg,
                background=bg,
                font=("TkDefaultFont", 10, "bold"),
            )
        self.agent_output.tag_configure(
            "mon_dim",
            foreground=palette["base00"],
            background=palette["base02"],
        )
        self.agent_output.tag_configure(
            "mon_err",
            foreground=palette["red"],
            background=palette["base02"],
            lmargin1=12,
            lmargin2=12,
        )

    def _configure_chat_tags(self) -> None:
        palette = SOLARIZED
        # Dark band = operator (user), lighter band = AI assistant
        self.chat_output.tag_configure(
            "chat_user",
            background=palette["base02"],
            foreground=palette["base1"],
            lmargin1=8,
            lmargin2=8,
            spacing1=4,
            spacing3=4,
        )
        self.chat_output.tag_configure(
            "chat_user_header",
            background=palette["base02"],
            foreground=palette["cyan"],
            font=("TkDefaultFont", 10, "bold"),
            lmargin1=8,
            lmargin2=8,
            spacing1=6,
        )
        self.chat_output.tag_configure(
            "chat_ai",
            background=palette["base03"],
            foreground=palette["base0"],
            lmargin1=8,
            lmargin2=8,
            spacing1=4,
            spacing3=4,
        )
        self.chat_output.tag_configure(
            "chat_ai_header",
            background=palette["base03"],
            foreground=palette["green"],
            font=("TkDefaultFont", 10, "bold"),
            lmargin1=8,
            lmargin2=8,
            spacing1=6,
        )

    def _build_chat_tab(self, root: ttk.Frame) -> None:
        form = ttk.LabelFrame(root, text="Operator Chat", padding=10)
        form.pack(fill=tk.X)
        ttk.Label(form, text="Target").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(form, textvariable=self.chat_target_var, width=28).grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Button(form, text="Ask Local AI", command=self._ask_chat_message).grid(row=0, column=2, padx=6)
        ttk.Label(form, text="Question or guidance").grid(row=1, column=0, sticky=tk.NW, pady=(8, 0))
        self.chat_input = tk.Text(form, wrap=tk.WORD, height=4)
        self._configure_text_widget(self.chat_input)
        self.chat_input.grid(row=1, column=1, columnspan=2, sticky=tk.EW, padx=6, pady=(8, 0))
        form.columnconfigure(1, weight=1)
        self.chat_output = tk.Text(root, wrap=tk.WORD, height=28)
        self._configure_text_widget(self.chat_output)
        self._configure_chat_tags()
        self.chat_output.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.chat_output.configure(state=tk.DISABLED)

    def _build_counts_tab(self, root: ttk.Frame) -> None:
        controls = ttk.Frame(root)
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="Runtime record counts and compact dashboard status.").pack(side=tk.LEFT)
        ttk.Button(controls, text="Refresh Counts", command=lambda: self._refresh_counts(nonblocking=True)).pack(side=tk.RIGHT)
        self.counts_output = tk.Text(root, wrap=tk.WORD, height=34)
        self._configure_text_widget(self.counts_output)
        self.counts_output.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.counts_output.configure(state=tk.DISABLED)

    def _build_config_tab(self, root: ttk.Frame) -> None:
        config_notebook = ttk.Notebook(root)
        config_notebook.pack(fill=tk.BOTH, expand=True)
        models_tab = ttk.Frame(config_notebook, padding=8)
        profiles_tab = ttk.Frame(config_notebook, padding=8)
        runtime_tab = ttk.Frame(config_notebook, padding=8)
        credentials_tab = ttk.Frame(config_notebook, padding=8)
        config_notebook.add(models_tab, text="Models")
        config_notebook.add(profiles_tab, text="Scope Profiles")
        config_notebook.add(runtime_tab, text="Runtime")
        config_notebook.add(credentials_tab, text="Credentials")

        models_frame = ttk.LabelFrame(models_tab, text="Ollama Model Roles", padding=10)
        models_frame.pack(fill=tk.X)
        self._build_model_role_controls(models_frame)
        model_actions = ttk.Frame(models_tab)
        model_actions.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(model_actions, text="Refresh Models", command=self._refresh_models).pack(side=tk.LEFT)
        ttk.Button(model_actions, text="Apply Model Roles", command=self._save_models).pack(side=tk.LEFT, padx=6)
        ttk.Button(model_actions, text="Warm Models", command=lambda: self._run_background("Warming models", self._warm_models)).pack(side=tk.LEFT, padx=6)
        ttk.Button(model_actions, text="Clear Models", command=lambda: self._run_background("Clearing models", self._clear_models)).pack(side=tk.LEFT, padx=6)

        self._build_scope_profile_controls(profiles_tab)
        self._build_runtime_tuning_controls(runtime_tab)
        self._build_credentials_controls(credentials_tab)

    def _build_model_role_controls(self, parent: ttk.Frame) -> None:
        payload = self.runtime.models_payload()
        available = list(payload.get("available_models", []))
        for row, role in enumerate(payload.get("roles", [])):
            if not isinstance(role, dict):
                continue
            role_id = str(role["role"])
            label = str(role["label"])
            processor = str(role["processor"]).upper()
            default_model = str(role["default_model"])
            selected = str(role["selected_model"])
            gpu_note = "CPU num_gpu=0" if role.get("num_gpu") == 0 else "GPU/default"
            ttk.Label(parent, text=f"{label} ({processor}, {gpu_note})").grid(row=row, column=0, sticky=tk.W, pady=2)
            var = tk.StringVar(value=selected)
            combo = ttk.Combobox(parent, textvariable=var, values=available, width=34, state="readonly")
            combo.grid(row=row, column=1, sticky=tk.W, padx=8, pady=2)
            processor_var = tk.StringVar(value=str(role.get("processor", "gpu")))
            processor_combo = ttk.Combobox(
                parent,
                textvariable=processor_var,
                values=["gpu", "cpu"],
                width=8,
                state="readonly",
            )
            processor_combo.grid(row=row, column=2, sticky=tk.W, padx=8, pady=2)
            ttk.Label(parent, text=f"Default: {default_model}").grid(row=row, column=3, sticky=tk.W, pady=2)
            self.model_vars[role_id] = var
            self.model_combos[role_id] = combo
            self.model_processor_vars[role_id] = processor_var
            self.model_processor_combos[role_id] = processor_combo

    def _build_scope_profile_controls(self, root: ttk.Frame) -> None:
        info = (
            "Scope profiles are operator presets. Custom profiles map to a built-in enforcement profile "
            "so policy and storage remain stable."
        )
        ttk.Label(root, text=info, wraplength=760, justify=tk.LEFT).pack(fill=tk.X)

        editor = ttk.LabelFrame(root, text="Add / Change Scope Profile", padding=10)
        editor.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(editor, text="Profile ID").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(editor, textvariable=self.scope_profile_id_var, width=24).grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(editor, text="Label").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(editor, textvariable=self.scope_profile_label_var, width=28).grid(row=0, column=3, sticky=tk.W, padx=6)
        ttk.Label(editor, text="Base enforcement").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Combobox(
            editor,
            textvariable=self.scope_profile_base_var,
            values=[ScopeProfile.HACK_THE_BOX.value, ScopeProfile.HACKERONE.value],
            width=18,
            state="readonly",
        ).grid(row=1, column=1, sticky=tk.W, padx=6, pady=(8, 0))
        ttk.Label(editor, text="Description").grid(row=1, column=2, sticky=tk.W, pady=(8, 0))
        ttk.Entry(editor, textvariable=self.scope_profile_description_var, width=42).grid(row=1, column=3, sticky=tk.EW, padx=6, pady=(8, 0))
        ttk.Button(editor, text="Save Profile", command=self._save_scope_profile).grid(row=2, column=0, sticky=tk.W, pady=(8, 0), padx=6)
        ttk.Button(editor, text="Delete Profile", command=self._delete_scope_profile).grid(row=2, column=1, sticky=tk.W, pady=(8, 0), padx=6)
        ttk.Button(editor, text="Clear Form", command=self._clear_scope_profile_form).grid(row=2, column=2, sticky=tk.W, pady=(8, 0), padx=6)
        ttk.Button(editor, text="Refresh Profiles", command=self._refresh_scope_profiles).grid(row=2, column=3, sticky=tk.W, pady=(8, 0), padx=6)
        editor.columnconfigure(3, weight=1)

        tree_frame = ttk.LabelFrame(root, text="Available Scope Profiles", padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.scope_profiles_tree = ttk.Treeview(
            tree_frame,
            columns=("id", "label", "base", "builtin", "description"),
            show="headings",
            height=10,
        )
        self.scope_profiles_tree.heading("id", text="Profile ID")
        self.scope_profiles_tree.heading("label", text="Label")
        self.scope_profiles_tree.heading("base", text="Base Enforcement")
        self.scope_profiles_tree.heading("builtin", text="Built-in")
        self.scope_profiles_tree.heading("description", text="Description")
        self.scope_profiles_tree.column("id", width=150)
        self.scope_profiles_tree.column("label", width=180)
        self.scope_profiles_tree.column("base", width=130)
        self.scope_profiles_tree.column("builtin", width=70)
        self.scope_profiles_tree.column("description", width=330)
        self.scope_profiles_tree.pack(fill=tk.BOTH, expand=True)
        self.scope_profiles_tree.bind("<<TreeviewSelect>>", self._on_scope_profile_selected)
        self._refresh_scope_profiles()

    def _build_runtime_tuning_controls(self, root: ttk.Frame) -> None:
        note = (
            "Tune local model patience and stale-run recovery. CPU timeout should generally be longer than GPU "
            "because slower reviewer/code lanes can legitimately take much longer to finish."
        )
        ttk.Label(root, text=note, wraplength=760, justify=tk.LEFT).pack(fill=tk.X)

        tuning = ttk.LabelFrame(root, text="Runtime Tuning", padding=10)
        tuning.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(tuning, text="GPU AI timeout (seconds)").grid(row=0, column=0, sticky=tk.W)
        self.gpu_ai_timeout_entry = ttk.Entry(tuning, textvariable=self.gpu_ai_timeout_var, width=10)
        self.gpu_ai_timeout_entry.grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(tuning, text="CPU AI timeout (seconds)").grid(row=0, column=2, sticky=tk.W)
        self.cpu_ai_timeout_entry = ttk.Entry(tuning, textvariable=self.cpu_ai_timeout_var, width=10)
        self.cpu_ai_timeout_entry.grid(row=0, column=3, sticky=tk.W, padx=6)
        ttk.Label(tuning, text="Stale run timeout (seconds)").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        self.stale_run_timeout_entry = ttk.Entry(tuning, textvariable=self.stale_run_timeout_var, width=10)
        self.stale_run_timeout_entry.grid(row=1, column=1, sticky=tk.W, padx=6, pady=(8, 0))
        ttk.Button(tuning, text="Apply Runtime Tuning", command=self._apply_runtime_tuning).grid(
            row=1, column=2, sticky=tk.W, padx=6, pady=(8, 0)
        )
        ttk.Label(tuning, textvariable=self.runtime_tuning_status_var, foreground=SOLARIZED["cyan"]).grid(
            row=2, column=0, columnspan=4, sticky=tk.W, pady=(8, 0)
        )

    def _build_credentials_controls(self, root: ttk.Frame) -> None:
        form = ttk.Frame(root)
        form.pack(fill=tk.X)

        notion = ttk.LabelFrame(form, text="Notion", padding=10)
        notion.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 8), pady=(0, 8))
        ttk.Label(
            notion,
            text="Publishes readable per-target notes, findings, and agent guidance into your Notion workspace. Local storage remains source of truth.",
            wraplength=360,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))
        ttk.Label(notion, text="API Key").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(notion, textvariable=self.notion_api_key_var, width=36, show="*").grid(row=1, column=1, padx=6)
        ttk.Label(notion, text="Parent Page ID").grid(row=2, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(notion, textvariable=self.notion_parent_page_id_var, width=36).grid(row=2, column=1, padx=6, pady=(6, 0))
        ttk.Label(notion, text="API Version").grid(row=3, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(notion, textvariable=self.notion_version_var, width=20).grid(row=3, column=1, sticky=tk.W, padx=6, pady=(6, 0))
        ttk.Button(notion, text="Save Notion", command=self._save_notion_credentials).grid(row=4, column=0, pady=(8, 0), sticky=tk.W)
        ttk.Button(notion, text="Clear Notion", command=lambda: self._clear_credentials("notion")).grid(row=4, column=1, pady=(8, 0), sticky=tk.W, padx=6)

        discord = ttk.LabelFrame(form, text="Discord", padding=10)
        discord.grid(row=0, column=1, sticky=tk.NSEW, padx=(0, 8), pady=(0, 8))
        ttk.Label(
            discord,
            text="Sends high-signal alerts only, such as approvals, likely findings, PoC research events, and repeated workflow failures.",
            wraplength=360,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))
        ttk.Label(discord, text="Webhook URL").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(discord, textvariable=self.discord_webhook_var, width=42, show="*").grid(row=1, column=1, padx=6)
        ttk.Button(discord, text="Save Discord", command=self._save_discord_credentials).grid(row=2, column=0, pady=(8, 0), sticky=tk.W)
        ttk.Button(discord, text="Clear Discord", command=lambda: self._clear_credentials("discord")).grid(row=2, column=1, pady=(8, 0), sticky=tk.W, padx=6)

        lab = ttk.LabelFrame(form, text="Lab / HTB", padding=10)
        lab.grid(row=1, column=0, sticky=tk.NSEW, padx=(0, 8), pady=(0, 8))
        ttk.Label(
            lab,
            text="Stores operator-provided lab credentials for bounded SMB/WinRM checks and flag verification. Leave blank until you intentionally provide creds.",
            wraplength=360,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))
        ttk.Label(lab, text="Username").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(lab, textvariable=self.lab_username_var, width=30).grid(row=1, column=1, padx=6)
        ttk.Label(lab, text="Password").grid(row=2, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(lab, textvariable=self.lab_password_var, width=30, show="*").grid(row=2, column=1, padx=6, pady=(6, 0))
        ttk.Label(lab, text="Domain").grid(row=3, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(lab, textvariable=self.lab_domain_var, width=30).grid(row=3, column=1, padx=6, pady=(6, 0))
        ttk.Button(lab, text="Save Lab", command=self._save_lab_credentials).grid(row=4, column=0, pady=(8, 0), sticky=tk.W)
        ttk.Button(lab, text="Clear Lab", command=lambda: self._clear_credentials("lab")).grid(row=4, column=1, pady=(8, 0), sticky=tk.W, padx=6)

        caido = ttk.LabelFrame(form, text="Caido", padding=10)
        caido.grid(row=1, column=1, sticky=tk.NSEW, padx=(0, 8), pady=(0, 8))
        ttk.Label(
            caido,
            text="Connects to local Caido GraphQL for HTTP traffic, replays, findings, and web-testing evidence references.",
            wraplength=360,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 8))
        ttk.Label(caido, text="GraphQL URL").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(caido, textvariable=self.caido_graphql_url_var, width=42).grid(row=1, column=1, padx=6)
        ttk.Label(caido, text="API Token").grid(row=2, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(caido, textvariable=self.caido_api_token_var, width=42, show="*").grid(row=2, column=1, padx=6, pady=(6, 0))
        ttk.Button(caido, text="Save Caido", command=self._save_caido_credentials).grid(row=3, column=0, pady=(8, 0), sticky=tk.W)
        ttk.Button(caido, text="Clear Caido", command=lambda: self._clear_credentials("caido")).grid(row=3, column=1, pady=(8, 0), sticky=tk.W, padx=6)
        ttk.Button(caido, text="Check Caido", command=self._check_caido).grid(row=4, column=0, pady=(8, 0), sticky=tk.W)

        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)
        ttk.Label(root, textvariable=self.credentials_status_var).pack(fill=tk.X, pady=(8, 0))
        self.credentials_output = tk.Text(root, wrap=tk.WORD, height=12)
        self._configure_text_widget(self.credentials_output)
        self.credentials_output.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.credentials_output.configure(state=tk.DISABLED)

    def _hydrate_target_fields_from_store(self) -> None:
        state = launcher_target_state(self.runtime)
        if not state:
            self.target_persistence_status_var.set("Active target: no persisted target found; defaults are shown.")
            return
        handle = str(state["handle"])
        display_name = str(state["display_name"])
        profile = str(state["profile"])
        active_ip = str(state.get("active_ip") or "").strip()
        generation = state.get("active_ip_generation")
        stale_count = int(state.get("stale_evidence_count", 0) or 0)

        self.scope_handle_var.set(handle)
        self.scope_display_name_var.set(display_name)
        self.scope_profile_var.set(profile)
        self.scope_active_ip_var.set(active_ip)
        self.chat_target_var.set(handle)
        self.guidance_target_var.set(handle)
        self.target_persistence_status_var.set(
            f"Active target: {handle} | active IP: {active_ip or 'not set'} | "
            f"generation: {generation if generation is not None else 'none'} | historical evidence: {stale_count}"
        )
        self._refresh_scope_table()

    def _install_target_warning_traces(self) -> None:
        for variable in (self.scope_handle_var, self.scope_active_ip_var):
            variable.trace_add("write", lambda *_args: self._refresh_target_ip_warnings())

    def _refresh_target_ip_warnings(self) -> None:
        warning = self._target_ip_warning(self.scope_handle_var.get(), self.scope_active_ip_var.get())
        self.scope_status_var.set(warning)

    def _target_ip_warning(self, handle: str, edited_ip: str) -> str:
        handle = handle.strip()
        edited_ip = edited_ip.strip()
        if not handle or not edited_ip:
            return ""
        target = self.runtime.store.get_target_by_handle(handle)
        if not target:
            return ""
        stored_ip = str(target.metadata.get("active_ip") or "").strip()
        if stored_ip and stored_ip != edited_ip:
            return f"Stored active IP is {stored_ip!r}. Applying will create a new active-IP generation."
        return ""

    # ── Target & Scope table ────────────────────────────────────────────

    _ASSET_TYPES = ("ip", "domain", "cidr", "wildcard")

    def _build_scope_target_frame(self, root: ttk.Frame) -> None:
        frame = ttk.LabelFrame(root, text="Target & Scope", padding=10)
        frame.pack(fill=tk.X, pady=8)

        # Row 0 — identity
        ttk.Label(frame, text="Handle").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.scope_handle_var, width=22).grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(frame, text="Display Name").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.scope_display_name_var, width=22).grid(row=0, column=3, sticky=tk.W, padx=6)
        ttk.Label(frame, text="Profile").grid(row=0, column=4, sticky=tk.W)
        self.scope_profile_combo = ttk.Combobox(
            frame,
            textvariable=self.scope_profile_var,
            values=[item["id"] for item in self.runtime.scope_profiles_payload()["profiles"]],
            width=14,
            state="readonly",
        )
        self.scope_profile_combo.grid(row=0, column=5, sticky=tk.W, padx=6)
        ttk.Checkbutton(frame, text="In scope", variable=self.scope_in_scope_var).grid(row=0, column=6, sticky=tk.W, padx=6)

        # Row 1 — active IP + warning
        ttk.Label(frame, text="Active IP").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Entry(frame, textvariable=self.scope_active_ip_var, width=22).grid(row=1, column=1, sticky=tk.W, padx=6, pady=(8, 0))
        ttk.Label(frame, textvariable=self.scope_status_var, foreground=SOLARIZED["orange"]).grid(
            row=1, column=2, columnspan=5, sticky=tk.W, pady=(8, 0)
        )

        # Row 2 — asset table
        tree_frame = ttk.Frame(frame)
        tree_frame.grid(row=2, column=0, columnspan=7, sticky=tk.EW, pady=(10, 0))
        cols = ("type", "asset", "ports", "rule")
        headings = ("Type", "Asset / Pattern", "Ports", "Rule")
        col_widths = (80, 340, 100, 70)
        self.scope_assets_tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            height=6,
            selectmode="browse",
        )
        for col, heading, width in zip(cols, headings, col_widths):
            self.scope_assets_tree.heading(col, text=heading)
            self.scope_assets_tree.column(col, width=width, stretch=(col == "asset"))
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.scope_assets_tree.yview)
        self.scope_assets_tree.configure(yscrollcommand=vsb.set)
        self.scope_assets_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.scope_assets_tree.bind("<Double-1>", lambda _e: self._edit_scope_asset())

        # Row 3 — table action buttons
        btn_row = ttk.Frame(frame)
        btn_row.grid(row=3, column=0, columnspan=7, sticky=tk.W, pady=(6, 0))
        ttk.Button(btn_row, text="+ Add", command=self._add_scope_asset).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="✎ Edit", command=self._edit_scope_asset).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(btn_row, text="✗ Remove", command=self._remove_scope_asset).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Separator(btn_row, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)
        ttk.Button(btn_row, text="Clear All", command=self._clear_scope_assets, style="Muted.TButton").pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Import Scope File", command=self._import_scope_and_refresh).pack(side=tk.LEFT, padx=(4, 0))

        # Row 4 — apply (never auto-runs)
        apply_row = ttk.Frame(frame)
        apply_row.grid(row=4, column=0, columnspan=7, sticky=tk.W, pady=(8, 0))
        ttk.Button(apply_row, text="Apply Target (no auto-run)", command=self._apply_scope_target).pack(side=tk.LEFT)
        ttk.Label(apply_row, textvariable=self.target_persistence_status_var, foreground=SOLARIZED["cyan"]).pack(
            side=tk.LEFT, padx=(12, 0)
        )

        frame.columnconfigure(3, weight=1)

    def _refresh_scope_table(self) -> None:
        if self.scope_assets_tree is None:
            return
        handle = self.scope_handle_var.get().strip()
        target = self.runtime.store.get_target_by_handle(handle) if handle else None
        db_assets = self.runtime.store.list_scope_assets(target.id) if target else []
        self._scope_asset_rows = [
            {
                "asset": asset.asset,
                "asset_type": asset.asset_type,
                "ports": str(asset.metadata.get("ports") or "*"),
                "scope_rule": str(asset.metadata.get("scope_rule") or "allow"),
            }
            for asset in db_assets
        ]
        self._repopulate_scope_tree()

    def _repopulate_scope_tree(self) -> None:
        if self.scope_assets_tree is None:
            return
        self.scope_assets_tree.delete(*self.scope_assets_tree.get_children())
        for index, row in enumerate(self._scope_asset_rows):
            self.scope_assets_tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    row.get("asset_type", "domain"),
                    row.get("asset", ""),
                    row.get("ports", "*"),
                    row.get("scope_rule", "allow"),
                ),
            )

    def _open_asset_dialog(self, existing: dict | None = None) -> dict | None:
        """Open a modal dialog to add or edit a scope asset row. Returns the row dict or None on cancel."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Asset" if existing is None else "Edit Asset")
        dialog.resizable(False, False)
        dialog.grab_set()
        palette = SOLARIZED

        asset_var = tk.StringVar(value=str(existing.get("asset", "")) if existing else "")
        type_var = tk.StringVar(value=str(existing.get("asset_type", "domain")) if existing else "domain")
        ports_var = tk.StringVar(value=str(existing.get("ports", "*")) if existing else "*")
        rule_var = tk.StringVar(value=str(existing.get("scope_rule", "allow")) if existing else "allow")

        form = ttk.Frame(dialog, padding=16)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Type").grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(form, textvariable=type_var, values=list(self._ASSET_TYPES), width=14, state="readonly").grid(
            row=0, column=1, sticky=tk.W, padx=8, pady=4
        )
        ttk.Label(form, text="Asset / Pattern").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(form, textvariable=asset_var, width=38).grid(row=1, column=1, sticky=tk.EW, padx=8, pady=4)
        ttk.Label(form, text="Ports").grid(row=2, column=0, sticky=tk.W)
        ports_entry = ttk.Entry(form, textvariable=ports_var, width=20)
        ports_entry.grid(row=2, column=1, sticky=tk.W, padx=8, pady=4)
        ttk.Label(form, text='* = all  |  e.g. 80,443,8000-8999', foreground=palette["base00"]).grid(
            row=2, column=2, sticky=tk.W, padx=4
        )
        ttk.Label(form, text="Rule").grid(row=3, column=0, sticky=tk.W)
        ttk.Combobox(form, textvariable=rule_var, values=["allow", "deny"], width=10, state="readonly").grid(
            row=3, column=1, sticky=tk.W, padx=8, pady=4
        )

        result: list[dict | None] = [None]

        def _ok() -> None:
            asset = asset_var.get().strip()
            if not asset:
                messagebox.showwarning("Asset required", "Asset / Pattern cannot be empty.", parent=dialog)
                return
            result[0] = {
                "asset": asset,
                "asset_type": type_var.get() or "domain",
                "ports": ports_var.get().strip() or "*",
                "scope_rule": rule_var.get() or "allow",
            }
            dialog.destroy()

        btn_row = ttk.Frame(form)
        btn_row.grid(row=4, column=0, columnspan=3, pady=(12, 0), sticky=tk.E)
        ttk.Button(btn_row, text="OK", command=_ok).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=(8, 0))

        dialog.bind("<Return>", lambda _e: _ok())
        dialog.bind("<Escape>", lambda _e: dialog.destroy())
        self.root.wait_window(dialog)
        return result[0]

    def _add_scope_asset(self) -> None:
        row = self._open_asset_dialog()
        if row is None:
            return
        self._scope_asset_rows.append(row)
        self._repopulate_scope_tree()

    def _edit_scope_asset(self) -> None:
        if self.scope_assets_tree is None:
            return
        selected = self.scope_assets_tree.selection()
        if not selected:
            return
        index = int(selected[0])
        updated = self._open_asset_dialog(existing=self._scope_asset_rows[index])
        if updated is None:
            return
        self._scope_asset_rows[index] = updated
        self._repopulate_scope_tree()
        if index < len(self.scope_assets_tree.get_children()):
            self.scope_assets_tree.selection_set(str(index))

    def _remove_scope_asset(self) -> None:
        if self.scope_assets_tree is None:
            return
        selected = self.scope_assets_tree.selection()
        if not selected:
            return
        index = int(selected[0])
        self._scope_asset_rows.pop(index)
        self._repopulate_scope_tree()

    def _clear_scope_assets(self) -> None:
        if not messagebox.askyesno("Clear All Assets", "Remove all scope assets from the staging table?\n(DB is unchanged until you click Apply.)"):
            return
        self._scope_asset_rows.clear()
        self._repopulate_scope_tree()

    def _apply_scope_target(self) -> None:
        handle = self.scope_handle_var.get().strip()
        if not handle:
            messagebox.showinfo("Target & Scope", "Handle is required.")
            return
        config = {
            "handle": handle,
            "display_name": self.scope_display_name_var.get().strip() or handle,
            "profile": self.scope_profile_var.get().strip(),
            "in_scope": bool(self.scope_in_scope_var.get()),
            "active_ip": self.scope_active_ip_var.get().strip(),
            "asset_rows": list(self._scope_asset_rows),
        }
        self._run_background("Applying target scope", lambda: self._apply_scope_target_sync(config))

    def _apply_scope_target_sync(self, config: dict[str, object]) -> str:
        with self._runtime_lock:
            target = self.runtime.replace_target_scope_assets(
                handle=str(config["handle"]),
                display_name=str(config["display_name"]),
                profile=self.runtime.resolve_scope_profile(str(config["profile"])),
                in_scope=bool(config["in_scope"]),
                active_ip=str(config["active_ip"]) if config["active_ip"] else None,
                asset_rows=list(config["asset_rows"]),
            )
            self.runtime.sync_findings_context_exports()
        self._queue.put(("hydrate_target", ""))
        self._queue.put(("refresh_tabs", ""))
        active_ip = target.metadata.get("active_ip") or "not set"
        return (
            f"Applied: {target.handle} ({target.profile.value}) | "
            f"assets={len(list(config['asset_rows']))} | active_ip={active_ip}"
        )

    def _import_scope_and_refresh(self) -> None:
        selected = filedialog.askopenfilename(
            title="Import Primordial Scope",
            filetypes=[
                ("Scope files", "*.json *.txt *.scope"),
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*"),
            ],
        )
        if not selected:
            return
        path = Path(selected)
        profile = self.scope_profile_var.get().strip()
        self._run_background("Importing scope", lambda: self._import_scope_and_refresh_sync(path, profile))

    def _import_scope_and_refresh_sync(self, path: Path, profile: str) -> str:
        with self._runtime_lock:
            outcome = self.runtime.import_scope(path, self.runtime.resolve_scope_profile(profile))
            self.runtime.sync_findings_context_exports()
        self._queue.put(("hydrate_target", ""))
        self._queue.put(("refresh_tabs", ""))
        return (
            f"Imported scope from {outcome['source']}: "
            f"targets={outcome['targets_imported']} assets={outcome['assets_imported']} "
            f"profile={outcome['profile']}"
        )

    def _check_system(self) -> None:
        self._run_background("System diagnostics", self._check_system_sync)

    def _check_system_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.diagnose_payload()
        return payload["summary"]

    def _start_web_server(self) -> None:
        if self._web_server and self._web_server.running:
            self._set_web_status()
            return
        try:
            self._web_server = WebConsoleThread(self.runtime, host=self.host_var.get().strip(), port=int(self.port_var.get()))
            self._web_server.start()
            self._set_web_status()
            self._write_output(f"Web console listening at {self._web_server.url}\n")
        except OSError as exc:
            messagebox.showerror("Web server failed", str(exc))

    def _stop_web_server(self) -> None:
        if self._web_server:
            self._web_server.stop()
        self._set_web_status()

    def _set_web_status(self) -> None:
        if self._web_server and self._web_server.running:
            self.web_status_var.set(f"Web server: running at {self._web_server.url}")
        else:
            self.web_status_var.set("Web server: stopped")

    def _open_browser(self) -> None:
        if not self._web_server or not self._web_server.running:
            self._start_web_server()
        if self._web_server:
            webbrowser.open(self._web_server.url)

    def _start_pirate_work(self) -> None:
        self._stop_requested.clear()
        self._start_web_server()
        config = self._workflow_config()
        self._run_background("Starting Pirate workflow", lambda: self._start_pirate_work_sync(config))

    def _workflow_config(self) -> dict[str, object]:
        return {
            "handle": self.target_var.get().strip() or "pirate.htb",
            "ip": self.ip_var.get().strip(),
            "title": self.title_var.get().strip() or "HTB Pirate Session",
            "cycles": max(1, int(self.cycles_var.get())),
            "max_executions": max(1, int(self.max_executions_var.get())),
        }

    def _start_pirate_work_sync(self, config: dict[str, object]) -> str:
        handle = str(config["handle"])
        ip = str(config["ip"])
        assets = [handle]
        if ip:
            assets.append(ip)
        with self._runtime_lock:
            active_session = self.runtime.store.get_active_session()
            if (
                active_session is None
                or active_session.methodology != MethodologyName.HTB_LAB
                or active_session.profile != ScopeProfile.HACK_THE_BOX
            ):
                self.runtime.start_session(
                    methodology=MethodologyName.HTB_LAB,
                    profile=ScopeProfile.HACK_THE_BOX,
                    title=str(config["title"]),
                )
            self.runtime.update_target_fields(
                handle=handle,
                display_name="HTB Pirate" if handle == "pirate.htb" else handle,
                profile=ScopeProfile.HACK_THE_BOX,
                assets=assets,
                active_ip=ip or None,
                in_scope=True,
                metadata={"target_kind": "htb_lab", "source": "gui_start_work"},
            )
            mode = self.runtime.execution_mode_payload()
            if str(mode["mode"]) == "continuous":
                report = self.runtime.run_tick(max_executions=int(config["max_executions"]))
                tick_summary = (
                    f"Continuous mode armed at {int(mode['interval_seconds'])}s. "
                    f"Immediate tick: created={len(report.created_tasks)} completed={len(report.completed_runs)}."
                )
            else:
                tick_summary = self._run_ticks_sync(
                    cycles=int(config["cycles"]),
                    max_executions=int(config["max_executions"]),
                )
            self.runtime.sync_findings_context_exports()
            status = self._status_snapshot_text()
        self._queue.put(("hydrate_target", ""))
        self._queue.put(("refresh_tabs", ""))
        return f"{tick_summary}\n\n{status}"

    def _update_htb_target(self) -> None:
        config = self._workflow_config()
        self._run_background("Updating HTB target", lambda: self._update_htb_target_sync(config))

    def _update_htb_target_sync(self, config: dict[str, object]) -> str:
        handle = str(config["handle"])
        ip = str(config["ip"]).strip()
        assets = [handle]
        if ip:
            assets.append(ip)
        with self._runtime_lock:
            target = self.runtime.update_target_fields(
                handle=handle,
                display_name="HTB Pirate" if handle == "pirate.htb" else handle,
                profile=ScopeProfile.HACK_THE_BOX,
                assets=assets,
                active_ip=ip or None,
                in_scope=True,
                metadata={"target_kind": "htb_lab", "source": "gui_htb_update"},
            )
            self.runtime.sync_findings_context_exports()
        self._queue.put(("hydrate_target", ""))
        self._queue.put(("refresh_tabs", ""))
        return (
            f"Updated HTB target {target.handle}. Active IP: "
            f"{target.metadata.get('active_ip') or 'not set'}. Future ticks will use stored target fields."
        )

    def _run_more_ticks(self) -> None:
        self._stop_requested.clear()
        config = self._workflow_config()
        self._run_background(
            "Running ticks",
            lambda: self._run_ticks_and_status(config),
        )

    def _run_ticks_and_status(self, config: dict[str, object]) -> str:
        with self._runtime_lock:
            tick_summary = self._run_ticks_sync(
                cycles=int(config["cycles"]),
                max_executions=int(config["max_executions"]),
            )
            self.runtime.sync_findings_context_exports()
            return f"{tick_summary}\n\n{self._status_snapshot_text()}"

    def _run_ticks_sync(self, *, cycles: int, max_executions: int) -> str:
        created = 0
        completed = 0
        lines = []
        for index in range(cycles):
            if self._stop_requested.is_set():
                lines.append(f"stopped before tick {index + 1}")
                break
            report = self.runtime.run_tick(max_executions=max_executions)
            created += len(report.created_tasks)
            completed += len(report.completed_runs)
            if report.created_tasks or report.completed_runs:
                lines.append(
                    f"tick {index + 1}: created={len(report.created_tasks)} completed={len(report.completed_runs)}"
                )
            if self._stop_requested.is_set():
                lines.append(f"stopped after tick {index + 1}")
                break
        if not lines:
            lines.append(
                "No runnable work was created or completed. Current state is blocked or already converged."
            )
        lines.append(f"total: created={created} completed={completed}")
        return "\n".join(lines)

    def _add_manual_target(self) -> None:
        config = {
            "handle": self.scope_handle_var.get().strip(),
            "display_name": self.scope_display_name_var.get().strip(),
            "profile": self.scope_profile_var.get().strip(),
            "assets": [
                item.strip()
                for item in self.scope_assets_var.get().split(",")
                if item.strip()
            ],
            "active_ip": self.scope_active_ip_var.get().strip(),
            "in_scope": bool(self.scope_in_scope_var.get()),
        }
        if not config["handle"]:
            messagebox.showinfo("Scope Management", "Target handle is required.")
            return
        self._run_background("Adding target", lambda: self._add_manual_target_sync(config))

    def _add_manual_target_sync(self, config: dict[str, object]) -> str:
        active_ip = str(config["active_ip"]).strip()
        assets = list(config["assets"]) or [str(config["handle"])]
        if active_ip and active_ip not in assets:
            assets.append(active_ip)
        with self._runtime_lock:
            target = self.runtime.update_target_fields(
                handle=str(config["handle"]),
                display_name=str(config["display_name"]) or str(config["handle"]),
                profile=self.runtime.resolve_scope_profile(str(config["profile"])),
                assets=assets,
                active_ip=active_ip or None,
                in_scope=bool(config["in_scope"]),
                metadata={"source": "gui_scope_management"},
            )
            self.runtime.sync_findings_context_exports()
        self._queue.put(("hydrate_target", ""))
        self._queue.put(("refresh_tabs", ""))
        return (
            f"Registered target {target.handle} ({target.profile.value}) with scope assets synced. "
            f"Active IP: {target.metadata.get('active_ip') or 'not set'}."
        )

    def _import_scope_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Import Primordial Scope",
            filetypes=[
                ("Scope files", "*.json *.txt *.scope"),
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*"),
            ],
        )
        if not selected:
            return
        path = Path(selected)
        profile = self.scope_profile_var.get().strip()
        self._run_background("Importing scope", lambda: self._import_scope_file_sync(path, profile))

    def _import_scope_file_sync(self, path: Path, profile: str) -> str:
        with self._runtime_lock:
            outcome = self.runtime.import_scope(path, self.runtime.resolve_scope_profile(profile))
            self.runtime.sync_findings_context_exports()
        self._queue.put(("refresh_tabs", ""))
        return (
            f"Imported scope from {outcome['source']}: "
            f"targets={outcome['targets_imported']} assets={outcome['assets_imported']} "
            f"profile={outcome['profile']}"
        )

    def _load_guidance(self) -> None:
        target = self.guidance_target_var.get().strip()
        if not target:
            messagebox.showinfo("Agent Guidance", "Guidance target is required.")
            return
        self._run_background("Loading guidance", lambda: self._load_guidance_sync(target))

    def _load_guidance_sync(self, target: str) -> str:
        with self._runtime_lock:
            payload = self.runtime.findings_context_payload(target=target, include_guidance=True)
        guidance = str(payload.get("workspace", {}).get("guidance", ""))
        self._queue.put(("set_guidance", guidance))
        workspace = payload.get("workspace", {})
        return f"Loaded guidance for {target} from {workspace.get('guidance_path', 'unknown path')}."

    def _save_guidance(self) -> None:
        target = self.guidance_target_var.get().strip()
        if not target:
            messagebox.showinfo("Agent Guidance", "Guidance target is required.")
            return
        body = self.guidance_input.get("1.0", tk.END).strip()
        self._run_background("Saving guidance", lambda: self._save_guidance_sync(target, body))

    def _save_guidance_sync(self, target: str, body: str) -> str:
        with self._runtime_lock:
            payload = self.runtime.update_target_guidance(target, body)
        self._queue.put(("refresh_tabs", ""))
        workspace = payload.get("workspace", {})
        return f"Saved guidance for {target} to {workspace.get('guidance_path', 'unknown path')}."

    def _toggle_execution_mode(self) -> None:
        current = self.execution_mode_var.get().strip().lower()
        target = "tick" if current == "continuous" else "continuous"
        self._run_background("Updating execution mode", lambda: self._set_execution_mode_sync(target))

    def _apply_tick_interval(self) -> None:
        self._run_background("Applying tick interval", self._apply_tick_interval_sync)

    def _apply_tick_interval_sync(self) -> str:
        current = self.execution_mode_var.get().strip().lower() or "tick"
        with self._runtime_lock:
            payload = self.runtime.update_execution_mode(
                current,
                interval_seconds=self._continuous_interval_seconds(),
            )
        self._queue.put(("refresh_tabs", ""))
        self._queue.put(("reschedule_execution_mode_poll", ""))
        interval = int(payload["interval_seconds"])
        if str(payload["mode"]) == "continuous":
            return f"Applied {interval}s tick interval. Continuous mode will use the new cadence on the next loop."
        return f"Applied {interval}s tick interval. It is now the default cadence for future continuous runs."

    def _apply_runtime_tuning(self) -> None:
        self._run_background("Applying runtime tuning", self._apply_runtime_tuning_sync)

    def _apply_runtime_tuning_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.update_runtime_tuning(
                gpu_ai_timeout_seconds=int(self.gpu_ai_timeout_var.get()),
                cpu_ai_timeout_seconds=int(self.cpu_ai_timeout_var.get()),
                stale_run_timeout_seconds=int(self.stale_run_timeout_var.get()),
            )
        self._queue.put(("refresh_tabs", ""))
        return (
            "Runtime tuning updated: "
            f"GPU AI timeout={payload['gpu_ai_timeout_seconds']}s, "
            f"CPU AI timeout={payload['cpu_ai_timeout_seconds']}s, "
            f"stale run timeout={payload['stale_run_timeout_seconds']}s."
        )

    def _set_execution_mode_sync(self, mode: str) -> str:
        with self._runtime_lock:
            payload = self.runtime.update_execution_mode(
                mode,
                interval_seconds=self._continuous_interval_seconds(),
            )
        self._queue.put(("refresh_tabs", ""))
        return self._format_execution_mode(payload)

    def _refresh_execution_mode(self, *, nonblocking: bool = False) -> bool:
        payload = self._runtime_read(self.runtime.execution_mode_payload, nonblocking=nonblocking)
        if payload is None:
            return False
        self.execution_mode_var.set(str(payload["mode"]))
        interval = int(payload["interval_seconds"])
        self._applied_execution_interval_seconds = interval
        focus_widget = self.root.focus_get()
        if self.continuous_interval_entry is None or focus_widget != self.continuous_interval_entry:
            self.continuous_interval_var.set(interval)
        self.execution_mode_status_var.set(self._format_execution_mode(payload))
        if payload["mode"] == "continuous":
            self.execution_toggle_text_var.set("Switch To Tick Mode")
            if self.run_more_ticks_button is not None:
                self.run_more_ticks_button.configure(style="Muted.TButton", state=tk.DISABLED)
            if self.stop_work_button is not None:
                self.stop_work_button.configure(style="TButton", state=tk.NORMAL)
        else:
            self.execution_toggle_text_var.set("Enable Continuous Mode")
            if self.run_more_ticks_button is not None:
                self.run_more_ticks_button.configure(style="TButton", state=tk.NORMAL)
            if self.stop_work_button is not None:
                self.stop_work_button.configure(style="TButton", state=tk.NORMAL)
        return True

    def _refresh_system_status(self, *, nonblocking: bool = False) -> bool:
        metrics = None if nonblocking else self.runtime.system_metrics_payload()
        tuning = self._runtime_read(self.runtime.runtime_tuning_payload, nonblocking=nonblocking)
        if isinstance(metrics, dict):
            self._apply_system_metrics(metrics)
        if tuning is not None:
            self._apply_runtime_tuning_payload(tuning)
        return True

    def _apply_system_metrics(self, payload: dict[str, object]) -> None:
        cpu = payload.get("cpu", {}) if isinstance(payload, dict) else {}
        gpu = payload.get("gpu", {}) if isinstance(payload, dict) else {}
        cpu_percent = float(cpu.get("percent", 0.0) or 0.0)
        gpu_percent = float(gpu.get("percent", 0.0) or 0.0)
        self.cpu_load_var.set(
            "CPU: "
            + (
                f"{cpu_percent:.1f}% | load1 {float(cpu.get('load_1', 0.0) or 0.0):.2f} / {cpu.get('cpu_count', '?')} cores"
                if cpu.get("available", True)
                else "unavailable"
            )
        )
        if self.cpu_progress is not None:
            self.cpu_progress.configure(value=max(0.0, min(100.0, cpu_percent)))
        if gpu.get("available"):
            memory_used = float(gpu.get("memory_used_mb", 0.0) or 0.0)
            memory_total = float(gpu.get("memory_total_mb", 0.0) or 0.0)
            self.gpu_load_var.set(
                f"GPU: {gpu_percent:.1f}% | VRAM {memory_used:.0f}/{memory_total:.0f} MB"
            )
        else:
            self.gpu_load_var.set(f"GPU: {gpu.get('error') or 'unavailable'}")
        if self.gpu_progress is not None:
            self.gpu_progress.configure(value=max(0.0, min(100.0, gpu_percent)))

    def _apply_runtime_tuning_payload(self, payload: dict[str, object]) -> None:
        self._sync_intvar_if_idle(
            self.gpu_ai_timeout_var,
            int(payload.get("gpu_ai_timeout_seconds", PrimordialRuntime.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU)),
            self.gpu_ai_timeout_entry,
        )
        self._sync_intvar_if_idle(
            self.cpu_ai_timeout_var,
            int(payload.get("cpu_ai_timeout_seconds", PrimordialRuntime.DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU)),
            self.cpu_ai_timeout_entry,
        )
        self._sync_intvar_if_idle(
            self.stale_run_timeout_var,
            int(payload.get("stale_run_timeout_seconds", PrimordialRuntime.DEFAULT_STALE_RUN_TIMEOUT_SECONDS)),
            self.stale_run_timeout_entry,
        )
        self.runtime_tuning_status_var.set(
            "Runtime tuning: "
            f"GPU AI timeout {payload.get('gpu_ai_timeout_seconds')}s | "
            f"CPU AI timeout {payload.get('cpu_ai_timeout_seconds')}s | "
            f"stale run timeout {payload.get('stale_run_timeout_seconds')}s"
        )

    def _format_execution_mode(self, payload: dict[str, object]) -> str:
        mode = str(payload.get("mode", "tick"))
        interval = int(payload.get("interval_seconds", PrimordialRuntime.DEFAULT_EXECUTION_INTERVAL_SECONDS))
        if mode == "continuous":
            return f"Execution mode: continuous/autonomous, bounded tick every {interval}s"
        return "Execution mode: tick/manual, only runs when you press a tick/work button"

    def _continuous_interval_seconds(self, default: int | None = None) -> int:
        try:
            return max(2, int(self.continuous_interval_var.get()))
        except (tk.TclError, ValueError):
            if default is not None:
                return max(2, int(default))
            return PrimordialRuntime.DEFAULT_EXECUTION_INTERVAL_SECONDS

    def _schedule_execution_mode_poll(self, delay_seconds: int | None = None) -> None:
        if self._execution_mode_after_id is not None:
            try:
                self.root.after_cancel(self._execution_mode_after_id)
            except tk.TclError:
                pass
            self._execution_mode_after_id = None
        if self._closed:
            return
        interval_seconds = max(2, int(delay_seconds or self._applied_execution_interval_seconds))
        self._execution_mode_after_id = self.root.after(interval_seconds * 1000, self._poll_execution_mode)

    def _poll_execution_mode(self) -> None:
        if self._closed:
            return
        self._execution_mode_after_id = None
        try:
            refreshed = self._refresh_execution_mode(nonblocking=True)
            if refreshed and self.execution_mode_var.get() == "continuous" and not self._continuous_tick_running:
                self._continuous_tick_running = True
                self._stop_requested.clear()
                self._run_background("Continuous tick", self._continuous_tick_sync)
        finally:
            if not self._closed:
                self._schedule_execution_mode_poll()

    def _continuous_tick_sync(self) -> str | None:
        try:
            config = self._workflow_config()
            with self._runtime_lock:
                payload = self.runtime.execution_mode_payload()
                if payload["mode"] != "continuous" or self._stop_requested.is_set():
                    return "Continuous mode is no longer active."
                report = self.runtime.run_tick(max_executions=int(config["max_executions"]))
                self.runtime.sync_findings_context_exports()
            self._queue.put(("refresh_tabs", ""))
            if not (report.created_tasks or report.completed_runs or report.decisions or report.events):
                return None
            return f"Continuous tick completed: {report.summary}"
        finally:
            self._continuous_tick_running = False

    def _stop_work(self) -> None:
        self._stop_requested.set()
        self.execution_mode_var.set("tick")
        self._run_background("Stopping work", self._stop_work_sync)

    def _stop_work_sync(self) -> str:
        with self._runtime_lock:
            outcome = self.runtime.stop_active_work()
        self._queue.put(("refresh_tabs", ""))
        return (
            "Stop requested. Active sessions paused="
            f"{outcome.get('paused_sessions', 0)}.\n"
            "In-flight model/tool calls are not force-killed; this launcher will stop before the next orchestration tick."
        )

    def _warm_models(self) -> str:
        with self._runtime_lock:
            outcome = self.runtime.warm_model_routes()
        lines = []
        for result in outcome["results"]:
            status = "ok" if result["ok"] else f"failed: {result['error']}"
            lines.append(f"{result['route']}: {result['model']} {status}")
        return "\n".join(lines)

    def _clear_models(self) -> str:
        with self._runtime_lock:
            outcome = self.runtime.clear_model_routes()
        lines = ["Model unload requested:"]
        for result in outcome["results"]:
            status = "ok" if result["ok"] else f"failed: {result['error']}"
            processor_hint = result.get("processor_hint", "default")
            lines.append(f"{result['route']}: {result['model']} ({processor_hint}) {status}")
        return "\n".join(lines)

    def _refresh_models(self) -> None:
        try:
            payload = self.runtime.models_payload()
            available = list(payload.get("available_models", []))
            role_payloads = {
                str(role["role"]): role
                for role in payload.get("roles", [])
                if isinstance(role, dict)
            }
            for role_id, combo in self.model_combos.items():
                combo["values"] = available
                role = role_payloads.get(role_id, {})
                if role.get("selected_model"):
                    self.model_vars[role_id].set(str(role["selected_model"]))
                if role.get("processor"):
                    self.model_processor_vars[role_id].set(str(role["processor"]))
            self._write_output("Ollama model list refreshed.\n")
        except Exception as exc:  # noqa: BLE001 - surface GUI operational errors
            messagebox.showerror("Model refresh failed", str(exc))

    def _save_models(self) -> None:
        selections = {role: var.get().strip() for role, var in self.model_vars.items() if var.get().strip()}
        processors = {
            role: var.get().strip().lower()
            for role, var in self.model_processor_vars.items()
            if var.get().strip()
        }
        self._run_background("Saving model roles", lambda: self._save_models_sync(selections, processors))

    def _save_models_sync(self, selections: dict[str, str], processors: dict[str, str]) -> str:
        with self._runtime_lock:
            payload = self.runtime.update_model_roles(selections, processors=processors)
        lines = ["Model role mappings updated:"]
        for role in payload.get("roles", []):
            if isinstance(role, dict):
                gpu_note = "num_gpu=0" if role.get("num_gpu") == 0 else "default GPU runtime"
                lines.append(f"- {role['label']}: {role['selected_model']} ({role['processor']}, {gpu_note})")
        return "\n".join(lines)

    def _refresh_scope_profiles(self) -> None:
        payload = self.runtime.scope_profiles_payload()
        profiles = [item for item in payload.get("profiles", []) if isinstance(item, dict)]
        profile_ids = [str(item["id"]) for item in profiles]
        if self.scope_profile_combo is not None:
            self.scope_profile_combo["values"] = profile_ids
            if self.scope_profile_var.get() not in profile_ids and profile_ids:
                self.scope_profile_var.set(profile_ids[0])
        if self.scope_profiles_tree is not None:
            self.scope_profiles_tree.delete(*self.scope_profiles_tree.get_children())
            for item in profiles:
                profile_id = str(item["id"])
                self.scope_profiles_tree.insert(
                    "",
                    tk.END,
                    iid=profile_id,
                    values=(
                        profile_id,
                        str(item.get("label", profile_id)),
                        str(item.get("base_profile", "")),
                        "yes" if item.get("builtin") else "no",
                        str(item.get("description", "")),
                    ),
                )

    def _on_scope_profile_selected(self, _event=None) -> None:
        if self.scope_profiles_tree is None:
            return
        selected = self.scope_profiles_tree.selection()
        if not selected:
            return
        profile_id = str(selected[0])
        payload = self.runtime.scope_profiles_payload()
        profile = next(
            (
                item
                for item in payload.get("profiles", [])
                if isinstance(item, dict) and str(item.get("id")) == profile_id
            ),
            None,
        )
        if not profile:
            return
        self.scope_profile_id_var.set(profile_id)
        self.scope_profile_label_var.set(str(profile.get("label", profile_id)))
        self.scope_profile_base_var.set(str(profile.get("base_profile", ScopeProfile.HACKERONE.value)))
        self.scope_profile_description_var.set(str(profile.get("description", "")))

    def _clear_scope_profile_form(self) -> None:
        self.scope_profile_id_var.set("")
        self.scope_profile_label_var.set("")
        self.scope_profile_base_var.set(ScopeProfile.HACK_THE_BOX.value)
        self.scope_profile_description_var.set("")
        if self.scope_profiles_tree is not None:
            self.scope_profiles_tree.selection_remove(*self.scope_profiles_tree.selection())

    def _save_scope_profile(self) -> None:
        profile_id = self.scope_profile_id_var.get().strip()
        label = self.scope_profile_label_var.get().strip()
        base_profile = self.scope_profile_base_var.get().strip()
        description = self.scope_profile_description_var.get().strip()
        if not profile_id and not label:
            messagebox.showinfo("Scope Profiles", "Profile ID or label is required.")
            return
        self._run_background(
            "Saving scope profile",
            lambda: self._save_scope_profile_sync(profile_id, label, base_profile, description),
        )

    def _save_scope_profile_sync(
        self,
        profile_id: str,
        label: str,
        base_profile: str,
        description: str,
    ) -> str:
        with self._runtime_lock:
            payload = self.runtime.upsert_scope_profile(
                profile_id=profile_id,
                label=label,
                base_profile=base_profile,
                description=description,
            )
        self._queue.put(("refresh_scope_profiles", ""))
        count = len(payload.get("profiles", []))
        return f"Saved scope profile. Available profiles: {count}."

    def _delete_scope_profile(self) -> None:
        profile_id = self.scope_profile_id_var.get().strip()
        if not profile_id:
            messagebox.showinfo("Scope Profiles", "Profile ID is required.")
            return
        if profile_id in {ScopeProfile.HACK_THE_BOX.value, ScopeProfile.HACKERONE.value}:
            messagebox.showinfo("Scope Profiles", "Built-in scope profiles cannot be deleted.")
            return
        self._run_background("Deleting scope profile", lambda: self._delete_scope_profile_sync(profile_id))

    def _delete_scope_profile_sync(self, profile_id: str) -> str:
        with self._runtime_lock:
            payload = self.runtime.delete_scope_profile(profile_id)
        self._queue.put(("refresh_scope_profiles", ""))
        count = len(payload.get("profiles", []))
        removed = "removed" if payload.get("removed") else "not found"
        return f"Scope profile {profile_id} {removed}. Available profiles: {count}."

    def _refresh_status(self) -> None:
        self._set_web_status()
        self._run_background("Refreshing status", self._refresh_status_sync)

    def _refresh_status_sync(self) -> str:
        with self._runtime_lock:
            self.runtime.sync_findings_context_exports()
            rendered = render_dashboard_text(self.runtime)
        self._queue.put(("refresh_tabs", ""))
        return rendered

    def _request_refresh_all_tabs(self) -> None:
        self._queue.put(("refresh_tabs", ""))

    def _ask_status(self) -> None:
        handle = self.target_var.get().strip() or "pirate.htb"
        self._run_background("Asking Primordial", lambda: self._status_text(handle))

    def _status_text(self, handle: str) -> str:
        with self._runtime_lock:
            payload = self.runtime.ask_operator_ai("status and next step", target=handle)
        if not payload["ok"]:
            return f"AI status failed: {payload['error']}"
        return f"model={payload['model']}\n{payload['answer']['body']}"

    def _status_snapshot_text(self) -> str:
        return render_dashboard_text(self.runtime)

    def _ask_chat_message(self) -> None:
        message = self.chat_input.get("1.0", tk.END).strip()
        target = self.chat_target_var.get().strip() or None
        if not message:
            messagebox.showinfo("Operator AI", "Question or guidance is required.")
            return
        self.chat_input.delete("1.0", tk.END)
        self._run_background("Asking operator AI", lambda: self._ask_chat_message_sync(message, target))

    def _ask_chat_message_sync(self, message: str, target: str | None) -> str:
        with self._runtime_lock:
            payload = self.runtime.ask_operator_ai(message, target=target)
        self._queue.put(("refresh_tabs", ""))
        if not payload["ok"]:
            return f"Operator AI failed: {payload['error']}"
        return f"Operator AI answered with {payload['model']}."

    def _runtime_read(self, loader: Callable[[], object], *, nonblocking: bool = False) -> object | None:
        acquired = self._runtime_lock.acquire(blocking=not nonblocking)
        if not acquired:
            return None
        try:
            return loader()
        finally:
            self._runtime_lock.release()

    def _sync_intvar_if_idle(self, variable: tk.IntVar, value: int, entry: ttk.Entry | None) -> None:
        focus_widget = self.root.focus_get()
        if entry is not None and focus_widget == entry:
            return
        variable.set(int(value))

    def _refresh_all_tabs(self) -> None:
        self._refresh_execution_mode()
        self._refresh_current_work()
        self._refresh_system_status()
        self._refresh_scope_profiles()
        self._refresh_agent_monitor()
        self._refresh_ai_thinking()
        self._refresh_chat()
        self._refresh_counts()
        self._refresh_credentials_status()

    def _refresh_all_tabs_nonblocking(self) -> None:
        self._refresh_execution_mode(nonblocking=True)
        self._refresh_current_work(nonblocking=True)
        self._refresh_system_status(nonblocking=True)
        self._refresh_scope_profiles()
        self._refresh_agent_monitor(nonblocking=True)
        self._refresh_ai_thinking(nonblocking=True)
        self._refresh_chat(nonblocking=True)
        self._refresh_counts(nonblocking=True)
        self._refresh_credentials_status(nonblocking=True)
        self._refresh_scope_table()

    # ── Agent Monitor (background-thread refresh, no runtime lock needed) ──

    def _trigger_agent_monitor_refresh(self) -> None:
        if self._agent_monitor_refresh_running:
            return
        self._agent_monitor_refresh_running = True
        Thread(target=self._background_agent_monitor_refresh, daemon=True).start()

    def _background_agent_monitor_refresh(self) -> None:
        try:
            store = self.runtime.store
            processor_map = self._processor_map_snapshot()
            runs = store.list_task_runs(limit=120)
            traces = store.list_traces(limit=200)
            tasks = store.list_tasks(limit=500)
            events = store.list_events(limit=100)
            task_map = {t.id: t for t in tasks}
            clear_after = self._agent_monitor_clear_after
            data = {
                "processor_map": processor_map,
                "runs": runs,
                "traces": traces,
                "tasks": tasks,
                "task_map": task_map,
                "events": events,
                "clear_after": clear_after,
            }
            self._queue.put(("agent_monitor_data", data))
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._agent_monitor_refresh_running = False

    @staticmethod
    def _as_utc(dt: datetime) -> datetime:
        """Ensure a datetime is UTC-aware; treat naive as UTC."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    def _render_agent_monitor(self, data: dict) -> None:
        processor_map = data["processor_map"]
        runs = data["runs"]
        traces = data["traces"]
        tasks = data["tasks"]
        task_map = data["task_map"]
        events = data["events"]
        clear_after = data["clear_after"]

        # Normalise clear_after to aware so comparisons are safe regardless of record timezone
        clear_after_utc = self._as_utc(clear_after) if clear_after is not None else None

        def after_clear(dt: datetime) -> bool:
            return clear_after_utc is None or self._as_utc(dt) > clear_after_utc

        widget = self.agent_output
        original_state = str(widget.cget("state"))
        if original_state == tk.DISABLED:
            widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)

        def insert(text: str, tag: str = "") -> None:
            if tag:
                widget.insert(tk.END, text, tag)
            else:
                widget.insert(tk.END, text)

        now = datetime.now(timezone.utc)

        # ── Task Status Overview ──────────────────────────────────────────
        insert("━━ TASK STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "mon_section_head")
        status_buckets: dict[str, list] = {}
        for task in tasks:
            key = task.status.value if task.status else "unknown"
            status_buckets.setdefault(key, []).append(task)
        ordered_statuses = ["running", "needs_approval", "pending", "waiting", "succeeded", "failed", "cancelled"]
        for status in ordered_statuses:
            bucket = status_buckets.get(status, [])
            if not bucket:
                continue
            tag = f"mon_{status}" if f"mon_{status}" in widget.tag_names() else "mon_dim"
            insert(f"  [{status.upper()}] {len(bucket)}", tag)
            for task in bucket[:5]:
                kind_label = task.kind.value if task.kind else "?"
                insert(f"  {kind_label} | {task.title[:60]}\n", "mon_dim")
            if len(bucket) > 5:
                insert(f"  … and {len(bucket) - 5} more\n", "mon_dim")
        insert("\n")

        # ── Recent Task Runs ──────────────────────────────────────────────
        insert("━━ RECENT RUNS (newest first) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "mon_section_head")
        visible_runs = [r for r in runs if after_clear(r.started_at)]
        if visible_runs:
            for run in visible_runs[:40]:
                task = task_map.get(str(run.task_id))
                title = task.title if task else "unknown task"
                kind = task.kind.value if task and task.kind else "?"
                processor = self._processor_for_task(task, processor_map)
                status_val = run.status.value if run.status else "unknown"
                role_val = run.role.value if run.role else "unknown-role"
                status_tag = f"mon_{status_val}" if f"mon_{status_val}" in widget.tag_names() else "mon_dim"
                try:
                    age = (now - self._as_utc(run.started_at)).total_seconds()
                    age_text = f"{age:.0f}s ago" if age < 3600 else f"{age / 3600:.1f}h ago"
                except Exception:  # noqa: BLE001
                    age_text = "?"
                insert(f"  {run.started_at.strftime('%H:%M:%S')} [{age_text}]  ", "mon_dim")
                insert(f"{status_val:<12}", status_tag)
                insert(f"  {role_val}  {run.model_name}  ({processor})\n", "mon_dim")
                insert(f"    {kind} → {title[:70]}\n", "mon_dim")
                if run.error:
                    insert(f"    ERR: {run.error[:120]}\n", "mon_err")
        else:
            insert("  No task runs in current window.\n", "mon_dim")
        insert("\n")

        # ── Agent Traces ──────────────────────────────────────────────────
        insert("━━ AGENT TRACES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "mon_section_head")
        visible_traces = [t for t in traces if after_clear(t.created_at)]
        if visible_traces:
            for trace in visible_traces[:60]:
                task = task_map.get(str(trace.task_id))
                title = task.title if task else "no task"
                model = trace.metadata.get("model") or (task.provider_model if task else "—")
                route = task.provider_route.value if task and task.provider_route else "—"
                role_val = trace.role.value if trace.role else "unknown-role"
                insert(f"  {trace.created_at.strftime('%H:%M:%S')}  ", "mon_dim")
                insert(f"{role_val}", "mon_pending")
                insert(f"  {trace.status}  {model}  {route}\n", "mon_dim")
                insert(f"    {title[:60]} → {trace.summary[:80]}\n", "mon_dim")
        else:
            insert("  No traces in current window.\n", "mon_dim")
        insert("\n")

        # ── System Events ─────────────────────────────────────────────────
        insert("━━ EVENTS (recent) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "mon_section_head")
        visible_events = [e for e in events if after_clear(e.created_at)][:30]
        if visible_events:
            for event in visible_events:
                is_err = "fail" in event.summary.lower() or "error" in event.summary.lower()
                tag = "mon_err" if is_err else "mon_dim"
                type_val = event.type.value if event.type else "event"
                insert(f"  {event.created_at.strftime('%H:%M:%S')}  {type_val}  {event.summary[:90]}\n", tag)
        else:
            insert("  No events in current window.\n", "mon_dim")

        widget.see(tk.END)
        if original_state == tk.DISABLED:
            widget.configure(state=tk.DISABLED)

    def _clear_agent_monitor_screen(self) -> None:
        self._agent_monitor_clear_after = datetime.now(timezone.utc)
        self._replace_text(self.agent_output, f"Screen cleared at {self._agent_monitor_clear_after.isoformat()}. Waiting for new events.")

    def _agent_monitor_interval_seconds(self) -> int:
        try:
            return max(2, int(self.agent_monitor_interval_var.get()))
        except (tk.TclError, ValueError):
            return 5

    def _refresh_agent_monitor(self, *, nonblocking: bool = False) -> bool:
        self._trigger_agent_monitor_refresh()
        return True

    def _refresh_current_work(self, *, nonblocking: bool = False) -> bool:
        payload = self._runtime_read(self.runtime.work_status_payload, nonblocking=nonblocking)
        if payload is None:
            return False
        gui_operations = list(self._active_operations.values())
        active = list(payload.get("active", []))
        queued = list(payload.get("queued", []))
        waiting = list(payload.get("waiting", []))
        recent = list(payload.get("recent", []))

        if gui_operations:
            now = datetime.now(timezone.utc)
            op_labels = []
            for operation in gui_operations:
                label = operation.get("label", "unknown")
                try:
                    started = datetime.fromisoformat(str(operation["started_at"]))
                    elapsed = int((now - started).total_seconds())
                    op_labels.append(f"{label} ({elapsed}s)")
                except Exception:  # noqa: BLE001
                    op_labels.append(label)
            summary = f"Current work: {', '.join(op_labels)}"
        else:
            summary = f"Current work: {payload.get('summary', 'idle')}"
        self.current_work_summary_var.set(summary)
        self.work_status_var.set(summary.replace("Current work:", "Work status:", 1))

        lines = [str(payload.get("summary", "No runtime status available."))]
        if gui_operations:
            lines.append("\nLauncher Operations")
            for operation in gui_operations:
                lines.append(
                    f"- {operation['label']} | status={operation['status']} | started={operation['started_at']}"
                )
        lines.append("\nRuntime Active Work")
        if active:
            for item in active:
                lines.append(self._format_work_item(item))
        else:
            lines.append("- none")
        lines.append("\nQueued Work")
        if queued:
            for item in queued[:8]:
                lines.append(self._format_work_item(item))
        else:
            lines.append("- none")
        lines.append("\nWaiting / Approval")
        if waiting:
            for item in waiting[:8]:
                lines.append(self._format_work_item(item))
        else:
            lines.append("- none")
        lines.append("\nRecent Activity")
        if recent:
            for item in recent[:6]:
                lines.append(self._format_work_item(item))
        else:
            lines.append("- none")
        self._replace_text(self.current_work_output, "\n".join(lines))
        return True

    def _format_work_item(self, item: object) -> str:
        if not isinstance(item, dict):
            return f"- {item}"
        title = item.get("title") or item.get("summary") or "untitled"
        agent = item.get("agent") or "unknown-agent"
        model = item.get("model") or "unknown-model"
        status = item.get("status") or "unknown-status"
        target = item.get("target") or "global"
        route = item.get("route") or "unknown-route"
        task_id = item.get("task_id") or item.get("run_id") or "no-id"
        return f"- {status} | {target} | {agent} | {model} | {route} | {title} | {task_id}"

    def _processor_for_task(self, task, processor_map: dict[str, str] | None = None) -> str:
        if not task or not task.provider_route:
            return "unknown-processor"
        route = task.provider_route.value
        role_by_route = {
            "local_fast": "local_fast",
            "local_deep": "local_deep",
            "local_compact": "local_compact",
            "local_code": "local_code",
            "cold_review": "local_code",
        }
        role = role_by_route.get(route)
        if not role:
            return "remote" if route == "remote_premium" else "unknown-processor"
        return (processor_map or self._processor_map_snapshot()).get(role, "unknown-processor")

    def _processor_map_snapshot(self) -> dict[str, str]:
        try:
            return dict(self.runtime._current_model_role_processors())
        except Exception:  # noqa: BLE001 - GUI display should not fail on settings drift
            return {}

    # ── AI Thinking (background-thread refresh, no runtime lock needed) ──

    def _trigger_ai_thinking_refresh(self) -> None:
        if self._ai_thinking_refresh_running:
            return
        self._ai_thinking_refresh_running = True
        Thread(target=self._background_ai_thinking_refresh, daemon=True).start()

    def _background_ai_thinking_refresh(self) -> None:
        try:
            store = self.runtime.store
            clear_after = self._ai_thinking_clear_after
            processor_map = self._processor_map_snapshot()
            task_map = {t.id: t for t in store.list_tasks(limit=500)}
            clear_after_utc = self._as_utc(clear_after) if clear_after is not None else None

            def after_clear(dt: datetime) -> bool:
                return clear_after_utc is None or self._as_utc(dt) > clear_after_utc

            model_runs = [
                item for item in store.list_task_runs(limit=160)
                if item.model_name and after_clear(item.started_at)
            ]
            ai_notes = [
                item for item in store.list_notes(limit=200)
                if item.metadata.get("kind") == "worker_ai_review" and after_clear(item.created_at)
            ]
            ai_traces = [
                item for item in store.list_traces(limit=250)
                if (
                    item.status == "ai_review_completed"
                    or item.metadata.get("kind") == "worker_ai_review"
                    or item.metadata.get("model")
                ) and after_clear(item.created_at)
            ]
            model_messages = [
                item for item in store.list_operator_messages(limit=120)
                if item.role == "assistant"
                and item.model
                and item.model != "deterministic-state"
                and after_clear(item.created_at)
            ]
            ai_failure_events = [
                item for item in store.list_events(limit=250)
                if (
                    "Worker AI generation unavailable" in item.summary
                    or "Operator state AI review unavailable" in item.summary
                ) and after_clear(item.created_at)
            ]
            self._queue.put(("ai_thinking_data", {
                "processor_map": processor_map,
                "task_map": task_map,
                "model_runs": model_runs,
                "ai_notes": ai_notes,
                "ai_traces": ai_traces,
                "model_messages": model_messages,
                "ai_failure_events": ai_failure_events,
                "clear_after": clear_after,
            }))
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._ai_thinking_refresh_running = False

    def _render_ai_thinking(self, data: dict) -> None:
        processor_map = data["processor_map"]
        task_map = data["task_map"]
        model_runs = data["model_runs"]
        ai_notes = data["ai_notes"]
        ai_traces = data["ai_traces"]
        model_messages = data["model_messages"]
        ai_failure_events = data["ai_failure_events"]
        clear_after = data["clear_after"]

        widget = self.ai_thinking_output
        original_state = str(widget.cget("state"))
        if original_state == tk.DISABLED:
            widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)

        def insert_block(agent_role: str, source: str, meta_lines: list[str], body: str) -> None:
            tag = self._ai_role_tag(agent_role)
            if tag not in widget.tag_names():
                tag = self._ai_role_tag("unknown-agent")
            speaker_tag = f"{tag}_speaker"
            widget.insert(tk.END, f"[{source}] {agent_role}\n", speaker_tag)
            for line in meta_lines:
                widget.insert(tk.END, "  " + line + "\n", "ai_dim")
            widget.insert(tk.END, body.strip() + "\n\n", tag)

        widget.insert(tk.END, "AI Thinking — model-generated content only\n", "ai_section_head")
        if clear_after:
            widget.insert(tk.END, f"Display cleared at {clear_after.isoformat()}; showing newer records only.\n", "ai_dim")
        widget.insert(tk.END, "\n")

        if ai_notes:
            widget.insert(tk.END, "── AUTONOMOUS WORKER REVIEWS ──────────────────────────────────────\n", "ai_section_head")
            for note in ai_notes:
                task = task_map.get(str(note.task_id))
                agent = task.role.value if task else "unknown-agent"
                route = task.provider_route.value if task and task.provider_route else "unknown-route"
                model = note.metadata.get("model") or (task.provider_model if task else "unknown-model")
                processor = note.metadata.get("processor") or self._processor_for_task(task, processor_map)
                elapsed = note.metadata.get("elapsed_seconds")
                elapsed_text = f"  elapsed={float(elapsed):.1f}s" if isinstance(elapsed, (int, float)) else ""
                meta = [
                    f"model={model}  processor={processor}  route={route}{elapsed_text}",
                    f"task={note.task_id or 'none'}  time={note.created_at.strftime('%H:%M:%S')}",
                ]
                if task:
                    meta.append(f"about={task.title[:80]}")
                insert_block(agent, "worker-review", meta, note.body)

        if model_runs:
            widget.insert(tk.END, "── RECENT MODEL RUNS ──────────────────────────────────────────────\n", "ai_section_head")
            for run in model_runs[:20]:
                task = task_map.get(str(run.task_id))
                processor = self._processor_for_task(task, processor_map)
                meta = [
                    f"model={run.model_name}  processor={processor}  route={run.provider_route.value}",
                    f"status={run.status.value}  task={run.task_id}  time={run.started_at.strftime('%H:%M:%S')}",
                ]
                if task:
                    meta.append(f"about={task.title[:80]}")
                body = run.trace_summary or run.error or "Model-backed task run completed without a detailed AI review note."
                insert_block(run.role.value, "model-run", meta, body)

        if ai_traces:
            widget.insert(tk.END, "── AI REVIEW TRACES ───────────────────────────────────────────────\n", "ai_section_head")
            for trace in ai_traces:
                task = task_map.get(str(trace.task_id))
                model = trace.metadata.get("model") or (task.provider_model if task else "unknown-model")
                processor = trace.metadata.get("processor") or self._processor_for_task(task, processor_map)
                route = task.provider_route.value if task and task.provider_route else "unknown-route"
                meta = [
                    f"model={model}  processor={processor}  route={route}",
                    f"status={trace.status}  task={trace.task_id}  time={trace.created_at.strftime('%H:%M:%S')}",
                ]
                if task:
                    meta.append(f"about={task.title[:80]}")
                insert_block(trace.role.value, "trace", meta, trace.summary)

        if ai_failure_events:
            widget.insert(tk.END, "── AI FAILURES / TIMEOUTS ─────────────────────────────────────────\n", "ai_section_head")
            for event in ai_failure_events[:20]:
                task = task_map.get(str(event.task_id)) if event.task_id else None
                model = event.metadata.get("model") if isinstance(event.metadata, dict) else None
                processor = self._processor_for_task(task, processor_map)
                route = task.provider_route.value if task and task.provider_route else "unknown-route"
                speaker = task.role.value if task else "Primordial AI"
                error_text = event.metadata.get("error") if isinstance(event.metadata, dict) else None
                meta = [
                    f"model={model or 'unknown-model'}  processor={processor}  route={route}",
                    f"task={event.task_id or 'none'}  time={event.created_at.strftime('%H:%M:%S')}",
                ]
                if task:
                    meta.append(f"about={task.title[:80]}")
                body = event.summary
                if error_text:
                    body += f"\nerror={error_text}"
                insert_block(speaker, "ai-failure", meta, body)

        if model_messages:
            widget.insert(tk.END, "── OPERATOR AI ANSWERS ────────────────────────────────────────────\n", "ai_section_head")
            for message in model_messages:
                meta = [
                    f"model={message.model}  target={message.target_id or 'global'}",
                    f"time={message.created_at.strftime('%H:%M:%S')}",
                ]
                insert_block("Primordial AI", "operator-chat", meta, message.body)

        if not (ai_notes or model_runs or ai_traces or ai_failure_events or model_messages):
            widget.insert(tk.END, "No AI-generated content in the current visible window.\n", "ai_dim")

        widget.see(tk.END)
        if original_state == tk.DISABLED:
            widget.configure(state=tk.DISABLED)

    def _refresh_ai_thinking(self, *, nonblocking: bool = False) -> bool:  # noqa: ARG002
        self._trigger_ai_thinking_refresh()
        return True

    def _is_after_thinking_clear(self, created_at: datetime) -> bool:
        return self._ai_thinking_clear_after is None or created_at > self._ai_thinking_clear_after

    def _clear_ai_thinking_screen(self) -> None:
        self._ai_thinking_clear_after = datetime.now(timezone.utc)
        self._replace_ai_thinking_text(
            f"Cleared at {self._ai_thinking_clear_after.isoformat()}.\nWaiting for new AI thinking records."
        )

    def _ai_thinking_interval_seconds(self) -> int:
        try:
            return max(1, int(self.ai_thinking_interval_var.get()))
        except (tk.TclError, ValueError):
            return 5

    # ── Chat (background-thread refresh, no runtime lock needed) ──

    def _trigger_chat_refresh(self) -> None:
        if self._chat_refresh_running:
            return
        self._chat_refresh_running = True
        Thread(target=self._background_chat_refresh, daemon=True).start()

    def _background_chat_refresh(self) -> None:
        try:
            messages = list(reversed(self.runtime.store.list_operator_messages(limit=80)))
            self._queue.put(("chat_data", messages))
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._chat_refresh_running = False

    def _render_chat_data(self, messages: list) -> None:
        widget = self.chat_output
        original_state = str(widget.cget("state"))
        if original_state == tk.DISABLED:
            widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        if not messages:
            widget.insert(tk.END, "No operator chat yet.\n")
        else:
            for message in messages:
                is_user = message.role != "assistant"
                header_tag = "chat_user_header" if is_user else "chat_ai_header"
                body_tag = "chat_user" if is_user else "chat_ai"
                label = "Operator" if is_user else "Primordial AI"
                model_suffix = f" | {message.model}" if message.model else ""
                header = f"{label}{model_suffix} | {message.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                widget.insert(tk.END, header, header_tag)
                widget.insert(tk.END, message.body.rstrip() + "\n\n", body_tag)
        widget.see(tk.END)
        if original_state == tk.DISABLED:
            widget.configure(state=tk.DISABLED)

    def _refresh_chat(self, *, nonblocking: bool = False) -> bool:  # noqa: ARG002
        self._trigger_chat_refresh()
        return True

    def _refresh_counts(self, *, nonblocking: bool = False) -> bool:
        loaded = self._runtime_read(
            lambda: (self.runtime.dashboard_payload(), render_dashboard_text(self.runtime)),
            nonblocking=nonblocking,
        )
        if loaded is None:
            return False
        dashboard, rendered = loaded
        counts = dashboard.get("counts", {})
        lines = ["Counts"]
        if isinstance(counts, dict):
            for key, value in sorted(counts.items()):
                lines.append(f"{key.replace('_', ' ')}\n{value}")
        lines.append("\nDashboard")
        lines.append(rendered)
        self._replace_text(self.counts_output, "\n".join(lines))
        return True

    def _refresh_credentials_status(self, *, nonblocking: bool = False) -> bool:
        payload = self._runtime_read(self.runtime.credentials_payload, nonblocking=nonblocking)
        if payload is None:
            return False
        self.credentials_status_var.set(f"Credentials: {payload.get('path')}")
        self._replace_text(self.credentials_output, self._format_credentials_payload(payload))
        return True

    def _format_credentials_payload(self, payload: dict[str, object]) -> str:
        lines = [f"credential_store={payload.get('path')}"]
        services = payload.get("services", {})
        if isinstance(services, dict):
            for service, fields in services.items():
                lines.append(f"\n{service}")
                if not isinstance(fields, dict):
                    continue
                for key, status in fields.items():
                    if not isinstance(status, dict):
                        continue
                    configured = "configured" if status.get("configured") else "missing"
                    hint = status.get("hint") or ""
                    suffix = f" {hint}" if hint else ""
                    lines.append(f"{key}: {configured} ({status.get('source')}){suffix}")
        return "\n".join(lines)

    def _save_notion_credentials(self) -> None:
        self._run_background("Saving Notion credentials", self._save_notion_credentials_sync)

    def _save_notion_credentials_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.set_notion_credentials(
                api_key=self.notion_api_key_var.get().strip(),
                parent_page_id=self.notion_parent_page_id_var.get().strip(),
                version=self.notion_version_var.get().strip(),
            )
        self._queue.put(("refresh_tabs", ""))
        return self._format_credentials_payload(payload)

    def _save_discord_credentials(self) -> None:
        self._run_background("Saving Discord credentials", self._save_discord_credentials_sync)

    def _save_discord_credentials_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.set_discord_credentials(webhook_url=self.discord_webhook_var.get().strip())
        self._queue.put(("refresh_tabs", ""))
        return self._format_credentials_payload(payload)

    def _save_lab_credentials(self) -> None:
        self._run_background("Saving lab credentials", self._save_lab_credentials_sync)

    def _save_lab_credentials_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.set_lab_credentials(
                username=self.lab_username_var.get().strip(),
                password=self.lab_password_var.get(),
                domain=self.lab_domain_var.get().strip(),
            )
        self._queue.put(("refresh_tabs", ""))
        return self._format_credentials_payload(payload)

    def _save_caido_credentials(self) -> None:
        self._run_background("Saving Caido credentials", self._save_caido_credentials_sync)

    def _save_caido_credentials_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.set_caido_credentials(
                graphql_url=self.caido_graphql_url_var.get().strip(),
                api_token=self.caido_api_token_var.get(),
            )
        self._queue.put(("refresh_tabs", ""))
        return self._format_credentials_payload(payload)

    def _clear_credentials(self, service: str) -> None:
        self._run_background(f"Clearing {service} credentials", lambda: self._clear_credentials_sync(service))

    def _clear_credentials_sync(self, service: str) -> str:
        with self._runtime_lock:
            payload = self.runtime.clear_credentials(service)
        self._queue.put(("refresh_tabs", ""))
        return self._format_credentials_payload(payload)

    def _check_caido(self) -> None:
        self._run_background("Checking Caido", self._check_caido_sync)

    def _check_caido_sync(self) -> str:
        with self._runtime_lock:
            payload = self.runtime.caido_status_payload(check_health=True)
        self._queue.put(("refresh_tabs", ""))
        return f"Caido configured={payload.get('configured')} ok={payload.get('ok')} error={payload.get('error')}"

    def _run_background(self, label: str, worker: Callable[[], str | None]) -> None:
        operation_id = self._begin_operation(label)
        self._refresh_current_work(nonblocking=True)
        Thread(target=self._background_entrypoint, args=(worker, operation_id), daemon=True).start()

    def _begin_operation(self, label: str) -> str:
        self._operation_seq += 1
        operation_id = f"gui_{self._operation_seq}"
        self._active_operations[operation_id] = {
            "id": operation_id,
            "label": label,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        return operation_id

    def _background_entrypoint(self, worker: Callable[[], str | None], operation_id: str) -> None:
        try:
            output = worker()
            if output:
                self._queue.put(("ok", output))
        except Exception as exc:  # pragma: no cover - GUI safety net
            self._queue.put(("error", str(exc)))
        finally:
            self._queue.put(("operation_done", operation_id))

    def _poll_queue(self) -> None:
        try:
            while True:
                status, message = self._queue.get_nowait()
                try:
                    self._dispatch_queue_message(status, message)
                except Exception as exc:  # noqa: BLE001
                    # A render error must never kill the poll loop — that would
                    # starve system_status_done and freeze the metrics display.
                    self._write_output(f"[queue handler error] {status}: {exc}\n")
        except Empty:
            pass
        if not self._closed:
            self.root.after(250, self._poll_queue)

    def _dispatch_queue_message(self, status: str, message: object) -> None:
        if status == "error":
            self.work_status_var.set("Work status: failed")
            messagebox.showerror("Primordial action failed", message)
        elif status == "refresh_tabs":
            self._refresh_all_tabs_nonblocking()
        elif status == "refresh_scope_profiles":
            self._refresh_scope_profiles()
        elif status == "reschedule_execution_mode_poll":
            self._schedule_execution_mode_poll()
        elif status == "system_status":
            payload = message if isinstance(message, dict) else {}
            metrics = payload.get("metrics")
            tuning = payload.get("tuning")
            if isinstance(metrics, dict):
                self._apply_system_metrics(metrics)
            if isinstance(tuning, dict):
                self._apply_runtime_tuning_payload(tuning)
        elif status == "system_status_done":
            self._system_status_refresh_running = False
        elif status == "agent_monitor_data":
            if isinstance(message, dict):
                self._render_agent_monitor(message)
        elif status == "ai_thinking_data":
            if isinstance(message, dict):
                self._render_ai_thinking(message)
        elif status == "chat_data":
            if isinstance(message, list):
                self._render_chat_data(message)
        elif status == "set_guidance":
            self.guidance_input.delete("1.0", tk.END)
            self.guidance_input.insert(tk.END, message)
        elif status == "hydrate_target":
            self._hydrate_target_fields_from_store()
        elif status == "operation_done":
            self._active_operations.pop(message, None)
            self._refresh_current_work()
        else:
            self._write_output(str(message) + "\n")
            self._refresh_current_work()

    def _poll_current_work(self) -> None:
        try:
            self._refresh_current_work(nonblocking=True)
        except tk.TclError:
            return
        if not self._closed:
            self.root.after(2000, self._poll_current_work)

    def _poll_agent_monitor(self) -> None:
        try:
            if self.agent_monitor_auto_var.get():
                self._trigger_agent_monitor_refresh()
        except tk.TclError:
            return
        if not self._closed:
            self.root.after(self._agent_monitor_interval_seconds() * 1000, self._poll_agent_monitor)

    def _poll_ai_thinking(self) -> None:
        try:
            if self.ai_thinking_auto_var.get():
                self._trigger_ai_thinking_refresh()
        except tk.TclError:
            return
        if not self._closed:
            self.root.after(self._ai_thinking_interval_seconds() * 1000, self._poll_ai_thinking)

    def _poll_system_metrics(self) -> None:
        if not self._system_status_refresh_running:
            self._system_status_refresh_running = True
            Thread(target=self._background_system_status_refresh, daemon=True).start()
        if not self._closed:
            self.root.after(2500, self._poll_system_metrics)

    def _background_system_status_refresh(self) -> None:
        try:
            metrics = self.runtime.system_metrics_payload()
            tuning = self._runtime_read(self.runtime.runtime_tuning_payload, nonblocking=True)
            self._queue.put(("system_status", {"metrics": metrics, "tuning": tuning}))
        finally:
            self._queue.put(("system_status_done", ""))

    def _write_output(self, message: str) -> None:
        self.output.insert(tk.END, message.rstrip() + "\n\n")
        self.output.see(tk.END)

    def _replace_ai_thinking_text(self, message: str) -> None:
        original_state = str(self.ai_thinking_output.cget("state"))
        if original_state == tk.DISABLED:
            self.ai_thinking_output.configure(state=tk.NORMAL)
        self.ai_thinking_output.delete("1.0", tk.END)
        self.ai_thinking_output.insert(tk.END, message.rstrip() + "\n")
        self._apply_ai_thinking_role_colors()
        self.ai_thinking_output.see(tk.END)
        if original_state == tk.DISABLED:
            self.ai_thinking_output.configure(state=tk.DISABLED)

    def _apply_ai_thinking_role_colors(self) -> None:
        line_count = int(self.ai_thinking_output.index("end-1c").split(".")[0])
        for line_no in range(1, line_count + 1):
            line = self.ai_thinking_output.get(f"{line_no}.0", f"{line_no}.end")
            if not line.startswith("speaker="):
                continue
            role = line.split("=", 1)[1].strip() or "unknown-agent"
            tag = self._ai_role_tag(role)
            if tag not in self.ai_thinking_output.tag_names():
                tag = self._ai_role_tag("unknown-agent")
            block_start = self._ai_thinking_block_start(line_no)
            block_end = self._ai_thinking_block_end(line_no, line_count)
            self.ai_thinking_output.tag_add(tag, f"{block_start}.0", f"{block_end}.end")
            self.ai_thinking_output.tag_add(f"{tag}_speaker", f"{line_no}.0", f"{line_no}.end")

    def _ai_thinking_block_start(self, speaker_line: int) -> int:
        line_no = speaker_line
        while line_no > 1:
            previous = self.ai_thinking_output.get(f"{line_no - 1}.0", f"{line_no - 1}.end").strip()
            if previous == "-------------------":
                return line_no - 1
            line_no -= 1
        return 1

    def _ai_thinking_block_end(self, speaker_line: int, line_count: int) -> int:
        line_no = speaker_line + 1
        while line_no <= line_count:
            current = self.ai_thinking_output.get(f"{line_no}.0", f"{line_no}.end").strip()
            next_line = (
                self.ai_thinking_output.get(f"{line_no + 1}.0", f"{line_no + 1}.end").strip()
                if line_no < line_count
                else ""
            )
            if current == "-------------------" and next_line.startswith("source="):
                return max(speaker_line, line_no - 1)
            line_no += 1
        return line_count

    def _ai_role_tag(self, role: str) -> str:
        safe = "".join(character if character.isalnum() else "_" for character in role.strip().lower())
        return f"ai_role_{safe or 'unknown_agent'}"

    def _replace_text(self, widget: tk.Text, message: str) -> None:
        original_state = str(widget.cget("state"))
        if original_state == tk.DISABLED:
            widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, message.rstrip() + "\n")
        widget.see(tk.END)
        if original_state == tk.DISABLED:
            widget.configure(state=tk.DISABLED)

    def _close(self) -> None:
        self._closed = True
        self._stop_requested.set()
        if self._web_server and self._web_server.running:
            self._web_server.stop()
        try:
            self.root.destroy()
        except tk.TclError:
            return

    def _handle_tk_exception(self, exc, value, traceback) -> None:
        if exc is KeyboardInterrupt:
            self._close()
            return
        messagebox.showerror("Primordial GUI error", str(value))


def launch_local_gui(runtime: PrimordialRuntime) -> int:
    return PrimordialLauncher(runtime).run()
