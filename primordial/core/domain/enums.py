from __future__ import annotations

from enum import StrEnum


class ScopeProfile(StrEnum):
    HACKERONE = "hackerone"
    HACK_THE_BOX = "hack_the_box"


class MethodologyPhase(StrEnum):
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    CHAINING = "chaining"
    BEHAVIOR_VERIFICATION = "behavior_verification"
    MEMORY_MAINTENANCE = "memory_maintenance"
    NOTIFICATION = "notification"


class MethodologyName(StrEnum):
    WEB_APP_CORE = "web_app_core"
    H1_SAFE_WEB = "h1_safe_web"
    HTB_LAB = "htb_lab"


class SessionStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    NEEDS_APPROVAL = "needs_approval"
    CANCELLED = "cancelled"


class TaskRunStatus(StrEnum):
    CLAIMED = "claimed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class TaskKind(StrEnum):
    RECON_SCAN = "recon_scan"
    SERVICE_DISCOVERY = "service_discovery"
    DNS_ENUMERATION = "dns_enumeration"
    WEB_CONTENT_DISCOVERY = "web_content_discovery"
    AD_ENUMERATION = "ad_enumeration"
    KERBEROS_USER_DISCOVERY = "kerberos_user_discovery"
    KERBEROS_ATTACK_CHECK = "kerberos_attack_check"
    CREDENTIALED_ACCESS_CHECK = "credentialed_access_check"
    EXPLOIT_RESEARCH = "exploit_research"
    POC_APPLICABILITY_VALIDATION = "poc_applicability_validation"
    ANALYZE_EVIDENCE = "analyze_evidence"
    VERIFY_HYPOTHESIS = "verify_hypothesis"
    CHAIN_CANDIDATES = "chain_candidates"
    VERIFY_AGENT_BEHAVIOR = "verify_agent_behavior"
    COMPACT_MEMORY = "compact_memory"
    SYNC_NOTION = "sync_notion"
    SEND_NOTIFICATION = "send_notification"
    REVIEW_PREMIUM_ESCALATION = "review_premium_escalation"


class EvidenceType(StrEnum):
    HTTP_REPLAY = "http_replay"
    REQUEST_FINGERPRINT = "request_fingerprint"
    PARAMETER = "parameter"
    AUTH_ARTIFACT = "auth_artifact"
    SCANNER_OUTPUT = "scanner_output"
    TOOL_OUTPUT = "tool_output"
    OPERATOR_NOTE = "operator_note"
    MODEL_REVIEW = "model_review"
    FINDING_ATTACHMENT = "finding_attachment"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    PARTIAL = "partial"
    VERIFIED = "verified"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class InterestStatus(StrEnum):
    OPEN = "open"
    VERIFIED = "verified"
    STALE = "stale"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class MemoryLayer(StrEnum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"


class MemoryStatus(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    STALE = "stale"
    INVALIDATED = "invalidated"


class RiskTier(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class SideEffectLevel(StrEnum):
    NONE = "none"
    READ_ONLY = "read_only"
    MUTATING = "mutating"
    EXPLOITATIVE = "exploitative"


class PrimitiveRuntime(StrEnum):
    HOST = "host"
    CONTAINER = "container"
    CAIDO = "caido"
    REMOTE = "remote"


class AgentRole(StrEnum):
    ORCHESTRATOR = "orchestrator"
    RECON_WORKER = "recon_worker"
    ANALYSIS_WORKER = "analysis_worker"
    EXPLOITATION_WORKER = "exploitation_worker"
    CHAINING_WORKER = "chaining_worker"
    MEMORY_WORKER = "memory_worker"
    BEHAVIOR_VERIFIER = "behavior_verifier"
    DEEP_REVIEWER = "deep_reviewer"
    CLAUDE_REVIEWER = "claude_reviewer"
    CODE_WORKER = "code_worker"


class ProviderRoute(StrEnum):
    LOCAL_FAST = "local_fast"
    LOCAL_DEEP = "local_deep"
    LOCAL_CODE = "local_code"
    LOCAL_COMPACT = "local_compact"
    COLD_REVIEW = "cold_review"
    REMOTE_PREMIUM = "remote_premium"


class PolicyVerdict(StrEnum):
    ALLOW = "allow"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(StrEnum):
    BOOTSTRAP = "bootstrap"
    SESSION_STARTED = "session_started"
    SCOPE_IMPORTED = "scope_imported"
    SCOPE_UPDATED = "scope_updated"
    NO_PROGRESS = "no_progress"
    TASK_PLANNED = "task_planned"
    TASK_STARTED = "task_started"
    TASK_DEFERRED = "task_deferred"
    TASK_RESUMED = "task_resumed"
    TASK_SUCCEEDED = "task_succeeded"
    TASK_FAILED = "task_failed"
    TASK_RETRIED = "task_retried"
    TASK_CHECKPOINTED = "task_checkpointed"
    TASK_BLOCKED = "task_blocked"
    TASK_NEEDS_APPROVAL = "task_needs_approval"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    POLICY_DECISION = "policy_decision"
    HANDOFF_CREATED = "handoff_created"
    MEMORY_PROMOTION = "memory_promotion"
    MEMORY_COMPACTION = "memory_compaction"
    FINDING_UPDATED = "finding_updated"
    ESCALATION_REQUESTED = "escalation_requested"
    ESCALATION_REVIEWED = "escalation_reviewed"
    NOTIFICATION_QUEUED = "notification_queued"
    NOTIFICATION_DELIVERED = "notification_delivered"
    NOTIFICATION_FAILED = "notification_failed"
    SYNC_QUEUED = "sync_queued"
    SYNC_COMPLETED = "sync_completed"
    SYNC_FAILED = "sync_failed"
    CREDENTIAL_UPDATED = "credential_updated"
    CREDENTIAL_CLEARED = "credential_cleared"
    OPERATOR_MESSAGE = "operator_message"
    OPERATOR_AI_RESPONSE = "operator_ai_response"


class AutonomyMode(StrEnum):
    MANUAL = "manual"
    ASSISTED = "assisted"
    SUPERVISED = "supervised"
    SUPERVISED_AUTO = "supervised_auto"
    HIGH_AUTONOMY = "high_autonomy"


class NotificationChannel(StrEnum):
    DISCORD = "discord"
    TUI = "tui"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    SUPPRESSED = "suppressed"
    FAILED = "failed"


class ExternalSyncKind(StrEnum):
    NOTION = "notion"


class ExternalSyncStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CheckpointKind(StrEnum):
    TASK = "task"
    SESSION = "session"
    MEMORY = "memory"


class ArtifactKind(StrEnum):
    TOOL_OUTPUT = "tool_output"
    CHECKPOINT = "checkpoint"
    EXPORT = "export"
    CAIDO_CAPTURE = "caido_capture"
    REPORT = "report"


class HandoffStatus(StrEnum):
    OPEN = "open"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalAction(StrEnum):
    APPROVE = "approve"
    DENY = "deny"
