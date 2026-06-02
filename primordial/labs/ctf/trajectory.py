from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import Any
import hashlib
import json
import re

from primordial.adapters.caido_redaction import redact_request_path
from primordial.core.domain.enums import AgentRole, ArtifactKind
from primordial.core.domain.models import ArtifactRecord, AttemptTrajectory, DocumentChunk, Task
from primordial.core.domain.model_utils import new_id
from primordial.core.sensitive_text import redact_sensitive_text
from primordial.labs.ctf.hardcode import FLAG_PATTERN


SECRET_QUERY_RE = re.compile(r"(?i)([?&](?:token|secret|password|passwd|api[_-]?key|access[_-]?key)=)[^&\s]+")
AUTH_HEADER_RE = re.compile(r"(?im)^(authorization\s*:\s*).+$")

_LOCKS: dict[str, Lock] = {}
_COUNTERS: defaultdict[str, int] = defaultdict(int)
_REGISTRY_LOCK = Lock()


def emit_attempt_trajectory(
    *,
    store: object,
    runtime_dir: Path,
    task: Task,
    kind: str,
    role: str | AgentRole,
    payload: dict[str, Any],
    evidence_refs: list[str] | tuple[str, ...] = (),
) -> AttemptTrajectory | None:
    target = store.get_target(task.target_id) if task.target_id else None
    if target is None or not _is_ctf_target(target.metadata):
        return None
    attempt_id = _attempt_id(target.metadata, target.id)
    lock = _lock_for(attempt_id)
    with lock:
        step_index = _COUNTERS[attempt_id]
        _COUNTERS[attempt_id] += 1
        trajectory = AttemptTrajectory(
            attempt_id=attempt_id,
            target_id=target.id,
            task_id=task.id,
            challenge_id=str(target.metadata.get("ctf_challenge_id") or target.handle),
            repo_relpath_sha=str(target.metadata.get("ctf_repo_relpath_sha") or ""),
            step_index=step_index,
            kind=kind,
            role=role.value if isinstance(role, AgentRole) else str(role),
            payload_json=redact_trajectory_payload(payload),
            evidence_refs=[ref for ref in evidence_refs if isinstance(ref, str) and ref.startswith("evidence:")],
            redacted=True,
        )
        _append_jsonl(runtime_dir, target_id=target.id, attempt_id=attempt_id, payload=trajectory.as_payload())
        store.insert_attempt_trajectory(trajectory)
        return trajectory


def complete_attempt_trajectory(attempt_id: str) -> None:
    with _REGISTRY_LOCK:
        _LOCKS.pop(attempt_id, None)
        _COUNTERS.pop(attempt_id, None)


def ingest_attempt_trajectory_summary(
    *,
    store: object,
    runtime_dir: Path,
    target_id: str,
    attempt_id: str,
    task_id: str | None,
    outcome: str,
    flag_verification: str = "",
    ground_truth_flag_sha256: str = "",
) -> ArtifactRecord | None:
    target = store.get_target(target_id)
    if target is None or not _is_ctf_target(target.metadata):
        return None
    rows = store.list_attempt_trajectories(target_id=target_id, attempt_id=attempt_id, limit=1000)
    if not rows:
        return None
    text = _trajectory_summary_text(rows, outcome=outcome, flag_verification=flag_verification)
    safe_text = str(redact_trajectory_payload({"text": text})["text"])
    source_sha = hashlib.sha256(safe_text.encode("utf-8")).hexdigest()
    artifact_dir = runtime_dir / "trajectory-rag" / _safe_fragment(target_id)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{_safe_fragment(attempt_id)}.md"
    artifact_path.write_text(safe_text + "\n", encoding="utf-8")
    artifact = ArtifactRecord(
        task_id=task_id,
        target_id=target_id,
        kind=ArtifactKind.RAG_DOCUMENT,
        path=str(artifact_path),
        sha256=hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
        size_bytes=artifact_path.stat().st_size,
        metadata={
            "corpus_type": "ctf_trajectory",
            "lab_id": target.metadata.get("ctf_lab_id", ""),
            "challenge_id": target.metadata.get("ctf_challenge_id", ""),
            "category": target.metadata.get("ctf_category", ""),
            "repo_relpath_sha": target.metadata.get("ctf_repo_relpath_sha", ""),
            "outcome": outcome,
            "flag_verification": flag_verification,
            "ground_truth_flag_sha256": ground_truth_flag_sha256,
        },
    )
    store.insert_artifact(artifact)
    store.insert_document_chunk(
        DocumentChunk(
            target_id=target_id,
            source_artifact_id=artifact.id,
            source_sha256=source_sha,
            chunk_index=0,
            title=f"CTF trajectory {target.handle}",
            text=safe_text,
            token_count=max(1, len(safe_text.split())),
            evidence_refs=[],
            metadata=dict(artifact.metadata),
        )
    )
    return artifact


def redact_trajectory_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): redact_trajectory_payload(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact_trajectory_payload(item) for item in value]
    if isinstance(value, bytes):
        return _redact_text(value.decode("utf-8", "replace"))
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(value: str) -> str:
    text = FLAG_PATTERN.sub("<redacted-flag>", redact_sensitive_text(str(value)))
    text = AUTH_HEADER_RE.sub(r"\1<redacted>", text)
    text = SECRET_QUERY_RE.sub(r"\1<redacted>", text)
    if "?" in text and text.startswith("/"):
        path, _, query = text.partition("?")
        return redact_request_path(path, query)
    return text


def _trajectory_summary_text(rows: list[AttemptTrajectory], *, outcome: str, flag_verification: str) -> str:
    lines = [f"outcome: {outcome}", f"flag_verification: {flag_verification}", ""]
    for row in rows:
        payload = json.dumps(row.payload_json, sort_keys=True)
        lines.append(f"{row.step_index}. {row.kind} {row.role}: {payload}")
    return "\n".join(lines)


def _append_jsonl(runtime_dir: Path, *, target_id: str, attempt_id: str, payload: dict[str, Any]) -> None:
    path = runtime_dir / "trajectories" / _safe_fragment(target_id) / f"{_safe_fragment(attempt_id)}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _lock_for(attempt_id: str) -> Lock:
    with _REGISTRY_LOCK:
        lock = _LOCKS.get(attempt_id)
        if lock is None:
            lock = Lock()
            _LOCKS[attempt_id] = lock
        return lock


def _is_ctf_target(metadata: dict[str, Any]) -> bool:
    return metadata.get("local_ctf_autonomous") is True or str(metadata.get("ctf_completion_indicator") or "") == "autonomous_flags"


def _attempt_id(metadata: dict[str, Any], target_id: str) -> str:
    return str(metadata.get("ctf_attempt_id") or f"attempt:{target_id}")


def _safe_fragment(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._")
    return text or new_id("trajectory")
