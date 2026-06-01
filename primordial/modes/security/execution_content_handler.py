from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveContentHandlerMixin:
    def _handle_web_content_discovery(self, task: Task, context: ContextSlice) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="web content discovery completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result

        bases = self._content_discovery_bases(target.id)
        if not bases:
            result.success = False
            result.error = "no reachable HTTP base URL is available for content discovery"
            return result

        words = self._content_discovery_words(target.metadata)
        discovered = self._run_web_content_discovery(bases, words)
        artifact = self._write_artifact(
            task,
            target.id,
            f"web-content-discovery-{self._safe_artifact_fragment(target.handle)}",
            {
                "target": target.as_payload(),
                "base_urls": bases,
                "word_count": len(words),
                "extensions": list(CONTENT_DISCOVERY_EXTENSIONS),
                "discovered": discovered,
            },
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"Web content discovery: {target.handle}",
            summary=self._summarize_content_discovery(discovered, bases, len(words)),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.82 if discovered else 0.7,
            freshness=0.96,
            artifact_path=artifact.path,
            metadata={
                "kind": "web_content_discovery",
                "base_urls": bases,
                "word_count": len(words),
                "extensions": list(CONTENT_DISCOVERY_EXTENSIONS),
                "discovered": discovered,
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="Web content discovery summary",
                body=self._build_content_discovery_note(discovered, bases, len(words)),
                confidence=0.76,
                freshness=0.92,
                metadata={"phase": task.phase.value, "path_count": len(discovered)},
            )
        )
        self._append_web_content_followups(task, target, result, evidence, discovered)
        return result

    def _append_web_content_followups(
        self,
        task: Task,
        target,
        result: TaskExecutionResult,
        evidence: EvidenceRecord,
        discovered: list[dict[str, object]],
    ) -> None:
        if discovered:
            result.interests.append(
                Interest(
                    target_id=target.id,
                    title="Discovered web path follow-up candidates",
                    summary="Bounded content discovery found reachable or access-controlled web paths for follow-up analysis.",
                    evidence_refs=[evidence.id],
                    status=InterestStatus.OPEN,
                    confidence=0.76,
                    metadata={"origin_task": task.id, "class": "web_content", "path_count": len(discovered)},
                )
            )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=f"Web content discovery found {len(discovered)} path(s) for {target.handle}",
                target_id=target.id,
                task_id=task.id,
                metadata={"path_count": len(discovered)},
            )
        )
