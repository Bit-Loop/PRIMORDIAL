from __future__ import annotations

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
from threading import RLock
import shutil
import subprocess
import sys
import time
from urllib import parse as urlparse

from primordial.adapters.caido import CaidoIntegrationService
from primordial.adapters.discord import DiscordNotificationService, validate_discord_webhook_url
from primordial.adapters.notion import NotionSyncService
from primordial.app.active_ip import active_ip_asset, active_ip_event, active_ip_note, build_active_ip_update
from primordial.app.caido_import import (
    caido_capture_evidence,
    caido_detail_error,
    caido_import_event,
    caido_import_response,
    caido_import_row,
    caido_request_payload,
    caido_scope_error,
    selected_caido_request_ids,
)
from primordial.app.deterministic_operator import (
    AUTH_SURFACE_TERMS,
    OPEN_PORT_TERMS,
    PROBLEM_TASK_TERMS,
    SCOPED_RECON_TERMS,
    TARGET_STATE_TERMS,
    deterministic_operator_facts,
    evidence_kind_set,
    flag_evidence_hits,
    merge_methodology_next_actions,
    operator_capability_sets,
    operator_question_has_any,
    render_deterministic_operator_answer,
)
from primordial.app.gpu_metrics import read_gpu_metrics
from primordial.app.model_evaluation import (
    model_eval_service,
    normalize_model_eval_processor,
    normalize_model_eval_providers,
    record_model_eval_payload,
)
from primordial.app.operator_ai import (
    OperatorAiDraft,
    OperatorAiRoute,
    assistant_message_from_draft,
    deterministic_state_draft,
    direct_state_draft,
    draft_with_ai_review,
    draft_with_escalation,
    guardrail_fallback_draft,
    model_success_draft,
    operator_ai_response_payload,
    operator_ai_route,
    operator_chat_system_prompt,
    operator_message_event,
    operator_question_message,
    operator_response_event,
    provider_failure_draft,
)
from primordial.app.rag_synthesis import (
    build_rag_synthesis_prompt,
    disallowed_model_response,
    final_rag_synthesis_response,
    prepare_rag_synthesis_context,
    provider_error_response,
    rag_synthesis_system_prompt,
    run_rag_synthesis_provider,
)
from primordial.app.scope_import import normalize_scope_assets
from primordial.app.work_status import (
    build_work_status_payload,
    credentialed_access_blocker,
    current_generation_evidence,
    missing_verified_path_blocker,
    poc_validation_blocker,
    stale_recon_blocker,
    work_status_capabilities,
)
from primordial.app.worker_runners import register_default_worker_runners
from primordial.core.config import AppConfig
from primordial.core.context.normalization import metadata_list_value, metadata_value
from primordial.core.credentials import CredentialStore
from primordial.core.domain.enums import (
    AgentRole,
    ArtifactKind,
    EvidenceType,
    EventType,
    InterestStatus,
    MethodologyPhase,
    MethodologyName,
    ProviderRoute,
    RiskTier,
    ScopeProfile,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
    VerificationStatus,
)
from primordial.core.domain.models import (
    DashboardSnapshot,
    ArtifactRecord,
    DocumentChunk,
    EventRecord,
    EvidenceRecord,
    Finding,
    Interest,
    Note,
    OperatorMessage,
    ScopeAsset,
    Session,
    Target,
    Task,
    json_ready,
    utc_now,
)
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.evidence import CredentialedAccessSurface, classify_credentialed_access_surface
from primordial.core.environment import EnvironmentClassification, EnvironmentClassifier
from primordial.core.findings_context import FindingsContextService
from primordial.core.intent import OperatorIntentRegistry
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.modules.registry import ModuleRegistry
from primordial.core.orchestration.policy import PolicyEngine
from primordial.core.orchestration.verifier import BehaviorVerifier
from primordial.core.orchestration.workflow import WorkflowOrchestrator
from primordial.core.primitives.catalog import PrimitiveCatalog
from primordial.core.providers.router import ProviderRouter
from primordial.core.providers.agent_chat import AgentChatClient, AgentChatSettings
from primordial.core.providers.lmstudio import LMStudioClient
from primordial.core.providers.lmstudio_tuning import LMStudioPerformanceTuner
from primordial.core.providers.ollama import OllamaClient, OllamaModelListResult
from primordial.core.providers.wrapper_prompts import WRAPPER_ROLE_PERSONALITY_PROMPTS, build_wrapper_system_prompt
from primordial.core.rag import DocumentIngestionService, RagContextBroker
from primordial.core.rag.citations import validate_rag_citations
from primordial.core.rag.embeddings import embedding_provider_from_config
from primordial.core.rag.importer import RagChunkImporter, RagImportOptions
from primordial.core.rag.vuln_sync import VulnFeedSyncer, VulnSyncOptions
from primordial.core.rag.vuln_hints import vulnerability_hints_from_results
from primordial.core.recovery.crash_journal import CrashJournal
from primordial.core.recovery.resume_tracker import ResumeTracker
from primordial.core.providers.scheduler import ModelScheduler
from primordial.core.skills import RuntimeSkillRegistry
from primordial.core.storage.runtime import RuntimeStore, _SCHEMA_VERSION
from primordial.core.validation import build_default_validation_registry
from primordial.core.workers import WorkerBroker
from primordial.modes.security.module import SecurityModeServices, build_security_mode_services

__all__ = tuple(name for name in globals() if not name.startswith("__"))
