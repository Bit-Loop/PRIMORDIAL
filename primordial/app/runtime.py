from __future__ import annotations

from primordial.app.runtime_deps import *  # noqa: F401,F403
from primordial.app.runtime_lifecycle import RuntimeLifecycleMixin
from primordial.app.runtime_self_test import RuntimeSelfTestMixin
from primordial.app.runtime_recovery import RuntimeRecoveryMixin
from primordial.app.runtime_intent_control import RuntimeIntentControlMixin
from primordial.app.runtime_execution_control import RuntimeExecutionControlMixin
from primordial.app.runtime_system_metrics import RuntimeSystemMetricsMixin
from primordial.app.runtime_environment import RuntimeEnvironmentMixin
from primordial.app.runtime_scope_management import RuntimeScopeManagementMixin
from primordial.app.runtime_scope_assets import RuntimeScopeAssetsMixin
from primordial.app.runtime_scope_profiles import RuntimeScopeProfilesMixin
from primordial.app.runtime_payloads import RuntimePayloadsMixin
from primordial.app.runtime_inspection import RuntimeInspectionMixin
from primordial.app.runtime_rag_index import RuntimeRagIndexMixin
from primordial.app.runtime_rag_imports import RuntimeRagImportsMixin
from primordial.app.runtime_rag_profiles import RuntimeRagProfilesMixin
from primordial.app.runtime_rag_answers import RuntimeRagAnswersMixin
from primordial.app.runtime_operator_ai import RuntimeOperatorAiMixin
from primordial.app.runtime_approval_inquiry import RuntimeApprovalInquiryMixin
from primordial.app.runtime_operator_context import RuntimeOperatorContextMixin
from primordial.app.runtime_operator_contract import RuntimeOperatorContractMixin
from primordial.app.runtime_operator_answers import RuntimeOperatorAnswersMixin
from primordial.app.runtime_operator_paths import RuntimeOperatorPathsMixin
from primordial.app.runtime_operator_evidence import RuntimeOperatorEvidenceMixin
from primordial.app.runtime_findings import RuntimeFindingsMixin
from primordial.app.runtime_credentials import RuntimeCredentialsMixin
from primordial.app.runtime_caido import RuntimeCaidoMixin
from primordial.app.runtime_caido_capture import RuntimeCaidoCaptureMixin
from primordial.app.runtime_model_catalog import RuntimeModelCatalogMixin
from primordial.app.runtime_model_eval import RuntimeModelEvalMixin
from primordial.app.runtime_wrapper_modes import RuntimeWrapperModesMixin
from primordial.app.runtime_agent_chat import RuntimeAgentChatMixin
from primordial.app.runtime_model_roles import RuntimeModelRolesMixin
from primordial.app.runtime_model_generation import RuntimeModelGenerationMixin


class PrimordialRuntime(
    RuntimeLifecycleMixin,
    RuntimeSelfTestMixin,
    RuntimeRecoveryMixin,
    RuntimeIntentControlMixin,
    RuntimeExecutionControlMixin,
    RuntimeSystemMetricsMixin,
    RuntimeEnvironmentMixin,
    RuntimeScopeManagementMixin,
    RuntimeScopeAssetsMixin,
    RuntimeScopeProfilesMixin,
    RuntimePayloadsMixin,
    RuntimeInspectionMixin,
    RuntimeRagIndexMixin,
    RuntimeRagImportsMixin,
    RuntimeRagProfilesMixin,
    RuntimeRagAnswersMixin,
    RuntimeOperatorAiMixin,
    RuntimeApprovalInquiryMixin,
    RuntimeOperatorContextMixin,
    RuntimeOperatorContractMixin,
    RuntimeOperatorAnswersMixin,
    RuntimeOperatorPathsMixin,
    RuntimeOperatorEvidenceMixin,
    RuntimeFindingsMixin,
    RuntimeCredentialsMixin,
    RuntimeCaidoMixin,
    RuntimeCaidoCaptureMixin,
    RuntimeModelCatalogMixin,
    RuntimeModelEvalMixin,
    RuntimeWrapperModesMixin,
    RuntimeAgentChatMixin,
    RuntimeModelRolesMixin,
    RuntimeModelGenerationMixin,
):
    EXECUTION_MODE_SETTING = "execution_mode"
    EXECUTION_MODE_INTERVAL_SETTING = "execution_mode_interval_seconds"
    EXECUTION_MODES = {"tick", "continuous"}
    DEFAULT_EXECUTION_INTERVAL_SECONDS = 30
    RUNTIME_TUNING_SETTING = "runtime_tuning"
    MODEL_WRAPPER_MODE_SETTING = "model_wrapper_mode"
    AGENT_CHAT_PROCESS_SETTING = "agent_chat_api_process"
    RAG_LAST_IMPORT_SETTING = "rag_last_import"
    RAG_LAST_VULN_SYNC_SETTING = "rag_last_vuln_sync"
    DEFAULT_WRAPPER_PRESET = "claude_sonnet"
    WRAPPER_EFFORTS = {"low", "medium", "high", "xhigh"}
    WRAPPER_PRESETS = {
        "claude_sonnet": {
            "label": "Claude Sonnet",
            "provider": "claude",
            "model": "sonnet",
            "effort": None,
        },
        "codex_gpt55_high": {
            "label": "GPT 5.5 High",
            "provider": "codex",
            "model": "gpt-5.5",
            "effort": "high",
        },
    }
    DEFAULT_WORKER_AI_TIMEOUT_SECONDS_GPU = 120
    DEFAULT_WORKER_AI_TIMEOUT_SECONDS_CPU = 300
    DEFAULT_STALE_RUN_TIMEOUT_SECONDS = 3600
    DEFAULT_MIN_FREE_CPU_RAM_MB = 2048
    DEFAULT_MIN_FREE_GPU_RAM_MB = 368
    MIN_GPU_AI_TIMEOUT_SECONDS = 15
    MIN_CPU_AI_TIMEOUT_SECONDS = 30
    MIN_STALE_RUN_TIMEOUT_SECONDS = 60
    MIN_FREE_CPU_RAM_MB = 0
    MIN_FREE_GPU_RAM_MB = 0
    METRICS_CACHE_TTL_SECONDS = 2.0
    WORKER_AI_TIMEOUT_SECONDS_GPU = 120
    WORKER_AI_TIMEOUT_SECONDS_CPU = 300
    SCOPE_PROFILE_PRESETS_SETTING = "scope_profile_presets"

    MODEL_ROLE_CONFIG = {
        "local_fast": {
            "label": "Orchestrator",
            "description": "Primary planning, orchestration, and broad analysis model.",
            "processor": "gpu",
            "default_model": "gemma4:e4b",
            "topology_field": "local_fast",
        },
        "local_deep": {
            "label": "Deep Reasoning",
            "description": "Harder reasoning, chain review, and subtle hypothesis analysis.",
            "processor": "gpu",
            "default_model": "deepseek-r1:8b",
            "topology_field": "local_deep",
        },
        "local_code": {
            "label": "Code / PoC Work",
            "description": "Mission-critical code, exploit research, and PoC adaptation work.",
            "processor": "cpu",
            "default_model": "qwen3-coder-next:q4_K_M",
            "topology_field": "local_code",
        },
        "local_compact": {
            "label": "Compact / Verifier",
            "description": "Memory compaction, cheap verification, and background classification.",
            "processor": "cpu",
            "default_model": "phi4-reasoning",
            "topology_field": "local_compact",
        },
    }

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.store = RuntimeStore(config.database_url, schema=config.database_schema)
        self.credentials = CredentialStore(config.credentials_path)
        self.catalog = PrimitiveCatalog()
        self.environment_classifier = self._load_environment_classifier(config.project_root)
        self.operator_intents = OperatorIntentRegistry(config.catalog_dir / "intents")
        self.event_bus = EventBus()
        self.modules = ModuleRegistry(self.event_bus)
        self.crash_journal = CrashJournal(config.crash_journal_path)
        self.policy = PolicyEngine(
            config.autonomy,
            credentials_status_loader=self.credentials_payload,
            daily_remote_cost_loader=self.store.get_daily_remote_cost_usd,
        )
        self.router = ProviderRouter(config.topology)
        self.agent_chat = AgentChatClient(
            AgentChatSettings(
                base_url=config.agent_chat_base_url,
                api_key=config.agent_chat_api_key,
                provider=config.agent_chat_provider,
                model=config.agent_chat_model,
                timeout_seconds=config.agent_chat_timeout_seconds,
                cwd=config.agent_chat_cwd,
                safe_guard=config.agent_chat_safe_guard,
                codex_sandbox=config.agent_chat_codex_sandbox,
                claude_permission_mode=config.agent_chat_claude_permission_mode,
            )
        )
        self.ollama = OllamaClient()
        self.rag_embedding_provider = embedding_provider_from_config(config.rag.embeddings)
        self.model_scheduler = ModelScheduler(config.autonomy)
        self.verifier = BehaviorVerifier()
        self.validation = build_default_validation_registry()
        self.skills = RuntimeSkillRegistry(config.skills_dir)
        self.findings_context = FindingsContextService(config.findings_dir, config.notion_exports_dir)
        self.rag = DocumentIngestionService(
            self.store,
            config.artifacts_dir,
            embedding_provider=self.rag_embedding_provider,
        )
        self.rag_context_broker = RagContextBroker(self.rag)
        self.resume_tracker = ResumeTracker(self.store, self.event_bus)
        self._last_recovery_status: dict[str, object] = {
            "previous_unclean_shutdown": False,
            "backoff_applied_seconds": 0.0,
            "recovered_runs": 0,
            "resumed_tasks": 0,
        }
        self.worker_broker = WorkerBroker(self.event_bus)
        self._metrics_lock = RLock()
        self._cpu_sample: tuple[int, int] | None = None
        self._network_sample: tuple[int, int, float] | None = None
        self._system_metrics_cache: dict[str, object] | None = None
        self._system_metrics_cache_at = 0.0
        self._register_modules()
        self._register_worker_runners()
        self.workflow = WorkflowOrchestrator(
            store=self.store,
            policy_engine=self.policy,
            provider_router=self.router,
            model_scheduler=self.model_scheduler,
            memory_service_loader=lambda: self.security.memory_service,
            verifier=self.verifier,
            primitive_resolver_loader=lambda: self.security.primitive_executor,
            worker_broker=self.worker_broker,
            validation_registry=self.validation,
            resume_tracker=self.resume_tracker,
            autonomy=config.autonomy,
            checkpoints_dir=config.checkpoints_dir,
            credentials_status_loader=self.credentials_payload,
            active_intent_policy_loader=self.intent_policy,
            active_intent_id_loader=lambda: self.active_operator_intent().id,
            rag_context_builder=self.build_rag_context_pack,
            resource_status_loader=lambda: self.system_metrics_payload(force_refresh=True),
            resource_reserve_loader=self.resource_reserve_payload,
            event_bus=self.event_bus,
        )

    @classmethod
    def from_env(cls) -> "PrimordialRuntime":
        return cls(AppConfig.from_env())
