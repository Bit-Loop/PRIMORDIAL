from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import subprocess
import traceback
from datetime import timedelta
from pathlib import Path
from typing import Callable, Protocol

from primordial.core.config import AutonomySettings
from primordial.core.context.normalization import metadata_bool_value, metadata_list_value, metadata_value
from primordial.core.domain.constants import AD_INDICATOR_PORTS, DNS_PORTS
from primordial.core.domain.enums import (
    AgentRole,
    CheckpointKind,
    EventType,
    ExternalSyncKind,
    NotificationChannel,
    NotificationStatus,
    PolicyVerdict,
    MethodologyPhase,
    ProviderRoute,
    TaskKind,
    TaskRunStatus,
    TaskStatus,
)
from primordial.core.domain.models import (
    AgentTrace,
    CheckpointRecord,
    DocumentChunk,
    EscalationPackage,
    EventRecord,
    ExternalSyncJob,
    NotificationRecord,
    Note,
    OrchestrationReport,
    PrimitiveManifest,
    Target,
    TargetMethodologyState,
    Task,
    TaskRun,
    utc_now,
)
from primordial.core.evidence import CredentialedAccessSurface, classify_credentialed_access_surface
from primordial.core.events.bus import EventBus, RuntimeSignal
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.orchestration.policy import PolicyEngine
from primordial.core.orchestration.verifier import BehaviorVerifier
from primordial.core.primitives.aliases import normalize_primitive_hint, primitives_for_hint
from primordial.core.providers.router import ProviderRouter
from primordial.core.providers.scheduler import ModelScheduler
from primordial.core.recovery.resume_tracker import ResumeTracker
from primordial.core.storage.runtime import RuntimeStore
from primordial.core.validation import ValidationContext, ValidationRegistry, ValidationStage
from primordial.core.workers import WorkerBroker
from primordial.modes.security.methodology import blueprint_for

__all__ = tuple(name for name in globals() if not name.startswith("__"))
