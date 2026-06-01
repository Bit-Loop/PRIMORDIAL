from __future__ import annotations

from primordial.core.orchestration.workflow_deps import (
    blueprint_for,
    DocumentChunk,
    json,
    metadata_bool_value,
    metadata_list_value,
    metadata_value,
    normalize_primitive_hint,
    re,
    Target,
    TaskKind,
)

from primordial.core.orchestration.workflow_types import (
    PlannedTargetAction,
    RemoteReviewAdmissionContext,
)

class WorkflowRagHintsMixin:
    def build_rag_task_hints(self, target: Target, *, query: str = "", limit: int = 8) -> dict[str, object]:
        return self._evaluate_rag_hint_admission(target, query=query, limit=limit)

    def _evaluate_rag_hint_admission(self, target: Target, *, query: str = "", limit: int = 8) -> dict[str, object]:
        evidence = self._current_generation_evidence(target, limit=200)
        chunks = self._rag_hint_chunks(target, query=query, limit=limit)
        if not chunks:
            return {"actions": [], "accepted": [], "rejected": []}
        context = self._remote_review_admission_context(target, evidence)
        results = [self._rag_hint_chunk_admission(target, chunk, evidence, context) for chunk in chunks]
        return self._merge_admission_results(results)

    def _rag_hint_chunk_admission(
        self,
        target: Target,
        chunk: DocumentChunk,
        evidence: list[object],
        context: RemoteReviewAdmissionContext,
    ) -> dict[str, list[object]]:
        recommendation, local_reject = self._rag_hint_recommendation(target, chunk, evidence)
        title = self._rag_hint_title(chunk, recommendation)
        corpus_type = self._rag_hint_corpus_type(chunk)
        if local_reject:
            rejection = self._rag_hint_rejection(chunk, title, corpus_type, local_reject)
            return self._admission_result(rejected=[rejection])
        assert recommendation is not None
        primitive_hint = self._normalized_primitive_hint(recommendation)
        reason = self._remote_review_action_reject_reason(
            target=target,
            recommendation=recommendation,
            available=context.available_primitives,
            current_evidence_ids=context.current_evidence_ids,
            rationale_refs=[],
            surface=context.surface,
        )
        if reason:
            rejection = self._rag_hint_rejection(chunk, title, corpus_type, reason, primitive_hint=primitive_hint)
            return self._admission_result(rejected=[rejection])
        task_kind = self.REMOTE_REVIEW_KIND_BY_PRIMITIVE[primitive_hint]
        if self._remote_review_task_exists(target, task_kind, context.active_generation):
            rejection = self._rag_hint_rejection(
                chunk, title, corpus_type, "equivalent current-generation task already exists", primitive_hint=primitive_hint
            )
            return self._admission_result(rejected=[rejection])
        action_refs = self._remote_review_action_refs(recommendation, [])
        action = self._rag_hint_planned_action(chunk, recommendation, corpus_type, task_kind, action_refs)
        accepted = self._rag_hint_acceptance(chunk, action, corpus_type, primitive_hint, task_kind, action_refs)
        return self._admission_result(actions=[action], accepted=[accepted])

    def _rag_hint_title(self, chunk: DocumentChunk, recommendation: dict[str, object] | None) -> str:
        return str(recommendation.get("title") if recommendation else chunk.title)

    def _rag_hint_corpus_type(self, chunk: DocumentChunk) -> str:
        return str(metadata_value(chunk.metadata, "corpus_type") or "operator_note")

    def _rag_hint_planned_action(
        self,
        chunk: DocumentChunk,
        recommendation: dict[str, object],
        corpus_type: str,
        task_kind: TaskKind,
        action_refs: list[str],
    ) -> PlannedTargetAction:
        title = self._rag_hint_title(chunk, recommendation)
        primitive_hint = self._normalized_primitive_hint(recommendation)
        return PlannedTargetAction(
            kind=task_kind,
            title=title,
            summary=str(recommendation.get("summary") or recommendation.get("rationale") or title),
            confidence=self._float_between_0_1(recommendation.get("confidence"), 0.68),
            phase_label=blueprint_for(task_kind).phase.value,
            subphase=f"rag_hint:{task_kind.value}",
            transition_reason=(
                "RAG direct task hint was citation-bound and deterministic admission validated "
                "current evidence, primitive coverage, scope, policy, and Operator Intent gates."
            ),
            prerequisite="current-generation evidence plus cited RAG chunk",
            metadata=self._rag_hint_action_metadata(chunk, recommendation, corpus_type, primitive_hint, action_refs),
        )

    def _rag_hint_action_metadata(
        self,
        chunk: DocumentChunk,
        recommendation: dict[str, object],
        corpus_type: str,
        primitive_hint: str,
        action_refs: list[str],
    ) -> dict[str, object]:
        classification = str(recommendation.get("applicability_classification") or "unknown")
        return {
            "rag_hint_admitted": True,
            "source_rag_chunk_id": chunk.id,
            "source_rag_artifact_id": chunk.source_artifact_id,
            "rag_corpus_type": corpus_type,
            "rag_source_trust": metadata_value(chunk.metadata, "source_trust"),
            "rag_hint_policy": metadata_value(chunk.metadata, "hint_policy"),
            "rag_walkthrough_hint": metadata_bool_value(chunk.metadata, "walkthrough_hint") or corpus_type == "htb_writeup",
            "rag_applicability_classification": classification,
            "rag_cve_ids": metadata_list_value(chunk.metadata, "cve_ids"),
            "primitive_hint": primitive_hint,
            "evidence_refs": action_refs,
            "supporting_evidence_refs": action_refs,
            "supporting_rag_chunk_ids": [chunk.id],
        }

    def _rag_hint_acceptance(
        self,
        chunk: DocumentChunk,
        action: PlannedTargetAction,
        corpus_type: str,
        primitive_hint: str,
        task_kind: TaskKind,
        action_refs: list[str],
    ) -> dict[str, object]:
        return {
            "rag_chunk_id": chunk.id,
            "title": action.title,
            "corpus_type": corpus_type,
            "primitive_hint": primitive_hint,
            "task_kind": task_kind.value,
            "evidence_refs": action_refs,
            "applicability_classification": action.metadata["rag_applicability_classification"],
        }

    def _rag_hint_rejection(
        self,
        chunk: DocumentChunk,
        title: str,
        corpus_type: str,
        reason: str,
        *,
        primitive_hint: str | None = None,
    ) -> dict[str, object]:
        payload = {"rag_chunk_id": chunk.id, "title": title, "corpus_type": corpus_type, "reason": reason}
        if primitive_hint is not None:
            payload["primitive_hint"] = primitive_hint
        return payload

    def _rag_hint_chunks(self, target: Target, *, query: str, limit: int) -> list[DocumentChunk]:
        terms = {
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", query.lower())
            if len(token) > 2
        }
        chunks = [
            chunk
            for chunk in self.store.list_document_chunks(target_id=target.id, limit=500)
            if str(metadata_value(chunk.metadata, "corpus_type") or "") in self.RAG_HINT_CORPUS_TYPES
            and str(metadata_value(chunk.metadata, "hint_policy") or "advisory") == "direct_task_hints"
            and str(metadata_value(chunk.metadata, "planner_visibility") or "normal") != "taxonomy_only"
        ]
        if not terms:
            return chunks[:limit]
        ranked: list[tuple[float, DocumentChunk]] = []
        for chunk in chunks:
            chunk_terms = {
                token
                for token in re.findall(r"[A-Za-z0-9_.:/-]+", f"{chunk.title}\n{chunk.text}".lower())
                if len(token) > 2
            }
            overlap = terms & chunk_terms
            score = len(overlap) / max(1, len(terms))
            ranked.append((score, chunk))
        ranked.sort(key=lambda item: (-item[0], item[1].created_at, item[1].chunk_index))
        return [chunk for _score, chunk in ranked[:limit]]

    def _rag_hint_recommendation(
        self,
        target: Target,
        chunk: DocumentChunk,
        evidence: list[object],
    ) -> tuple[dict[str, object] | None, str]:
        corpus_type = str(metadata_value(chunk.metadata, "corpus_type") or "")
        if corpus_type == "mitre_attack" or str(metadata_value(chunk.metadata, "planner_visibility") or "") == "taxonomy_only":
            return None, "taxonomy-only RAG chunks cannot drive action selection"
        primitive_hint = self._rag_hint_primitive(chunk)
        if not primitive_hint:
            return None, "RAG chunk does not imply a supported primitive hint"
        if not evidence:
            return None, "RAG direct hints require current-generation target evidence"
        classification = self._rag_applicability_classification(chunk, evidence)
        if classification == "rejected":
            return None, "RAG applicability classified rejected"
        evidence_refs = [str(item.id) for item in evidence[:8] if getattr(item, "id", None)]
        cve_ids = metadata_list_value(chunk.metadata, "cve_ids")
        cve_label = ", ".join(str(item) for item in cve_ids[:3]) if cve_ids else ""
        if corpus_type == "htb_writeup":
            title = f"HTB writeup hint: {chunk.title}"
            summary = (
                "Operator-enabled HTB writeup material suggests this next step. "
                "Treat this as walkthrough guidance only; current evidence and policy remain authoritative."
            )
        elif primitive_hint == "poc-applicability-validation":
            title = f"RAG CVE applicability review: {cve_label or chunk.title}"
            summary = (
                "CVE/exploit RAG material should be checked against current service/version evidence "
                f"before any execution path. Applicability is currently {classification}."
            )
        else:
            title = f"RAG exploit research hint: {chunk.title}"
            summary = "Exploit/CVE RAG material suggests a bounded research or triage step."
        return (
            {
                "title": title[:180],
                "summary": summary,
                "primitive_hint": primitive_hint,
                "target": target.handle,
                "evidence_refs": evidence_refs,
                "confidence": 0.72 if classification == "likely" else 0.62,
                "applicability_classification": classification,
            },
            "",
        )

    def _rag_hint_primitive(self, chunk: DocumentChunk) -> str:
        metadata_hint = normalize_primitive_hint(metadata_value(chunk.metadata, "primitive_hint"))
        if metadata_hint:
            return metadata_hint
        corpus_type = str(metadata_value(chunk.metadata, "corpus_type") or "")
        text = f"{chunk.title}\n{chunk.text}".lower()
        if corpus_type in {"cve_advisory", "exploit_note"}:
            if re.search(r"\b(cve-\d{4}-\d{4,7}|poc|exploit|vulnerab|searchsploit)\b", text):
                return "poc-applicability-validation"
            return "exploit-research"
        if corpus_type == "htb_writeup":
            if re.search(r"\b(ffuf|feroxbuster|gobuster|dirsearch|directory|content discovery|hidden path|endpoint)\b", text):
                return "content-discovery"
            if re.search(r"\b(vhost|virtual host|subdomain|zone transfer|dns)\b", text):
                return "dns-enumeration"
            if re.search(r"\b(smb|ldap|rpc|active directory|domain controller)\b", text):
                return "ad-enumeration"
            if re.search(r"\b(kerberos|asrep|kerberoast|principal)\b", text):
                return "kerberos-attack-check"
            if re.search(r"\b(credential|winrm|evil-winrm|psexec|smb login)\b", text):
                return "credentialed-access-check"
            if re.search(r"\b(cve-\d{4}-\d{4,7}|poc|exploit|searchsploit)\b", text):
                return "poc-applicability-validation"
        return ""

    def _rag_applicability_classification(self, chunk: DocumentChunk, evidence: list[object]) -> str:
        override = str(chunk.metadata.get("applicability_classification") or "").strip().lower()
        if override in {"likely", "unknown", "rejected"}:
            return override
        text = f"{chunk.title}\n{chunk.text}".lower()
        if re.search(r"\b(not affected|unaffected|does not affect|not vulnerable|outside (the )?version range)\b", text):
            return "rejected"
        corpus_type = str(chunk.metadata.get("corpus_type") or "")
        if corpus_type == "htb_writeup":
            return "unknown"
        evidence_terms = self._rag_evidence_terms(evidence)
        chunk_terms = {
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", text)
            if len(token) > 2
        }
        service_terms = {
            "openssh",
            "ssh",
            "nginx",
            "apache",
            "httpd",
            "iis",
            "tomcat",
            "wordpress",
            "smb",
            "samba",
            "ldap",
            "kerberos",
            "windows",
            "linux",
            "php",
            "node",
            "express",
            "nagios",
            "jenkins",
            "postgres",
            "mysql",
            "mssql",
        }
        if (evidence_terms & chunk_terms & service_terms) and re.search(r"\b(cve-\d{4}-\d{4,7}|poc|exploit|vulnerab)\b", text):
            return "likely"
        return "unknown"

    def _rag_evidence_terms(self, evidence: list[object]) -> set[str]:
        blob = "\n".join(json.dumps(getattr(item, "as_payload", lambda: {})(), sort_keys=True, default=str).lower() for item in evidence)
        return {
            token
            for token in re.findall(r"[A-Za-z0-9_.:/-]+", blob)
            if len(token) > 2
        }
