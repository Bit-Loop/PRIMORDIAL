from __future__ import annotations

from typing import Any

from primordial.core.domain.enums import AgentRole, ProviderRoute, TaskKind
from primordial.core.web.payload_views import control_plane_payload


class WebRuntimeViewsMixin:
    def _control_plane_payload(self, *, target: str | None = None, live_metrics: bool = False) -> dict[str, Any]:
        return control_plane_payload(self, target=target, live_metrics=live_metrics)

    def _system_metrics_payload(self) -> dict[str, Any]:
        metrics = self.runtime.system_metrics_payload(force_refresh=True)
        network = metrics.get("network", {}) if isinstance(metrics.get("network"), dict) else {}
        gpu_metrics = metrics.get("gpu", {}) if isinstance(metrics.get("gpu"), dict) else {}
        return {
            "systemMetrics": metrics,
            "runtime": {
                "cpu": self._metric_ratio(metrics, "cpu"),
                "gpu": self._metric_ratio(metrics, "gpu"),
                "mem": self._memory_ratio(metrics),
                "netIn": str(network.get("rx_label") or "0 B/s"),
                "netOut": str(network.get("tx_label") or "0 B/s"),
                "gpuMemory": self._gpu_memory_payload(gpu_metrics),
            },
        }

    def _models_view(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        roles = payload.get("roles", [])
        if not isinstance(roles, list):
            return []
        ollama = payload.get("ollama", {}) if isinstance(payload.get("ollama"), dict) else {}
        return [
            {
                "route": str(role.get("role", "")),
                "label": str(role.get("label", role.get("role", ""))),
                "model": str(role.get("selected_model") or role.get("default_model") or ""),
                "loaded": bool(ollama.get("ok")),
                "hot": bool(ollama.get("ok")),
                "ctx": int(role.get("context_window", 0) or 0),
                "processor": str(role.get("processor", "")),
                "available": payload.get("available_models", []),
                "metrics": role.get("metrics"),
            }
            for role in roles
            if isinstance(role, dict)
        ]

    def _intent_policy_flags(self, policy: dict[str, Any]) -> dict[str, bool]:
        kerberos = policy.get("kerberos_policy", {}) if isinstance(policy.get("kerberos_policy"), dict) else {}
        credential = policy.get("credential_policy", {}) if isinstance(policy.get("credential_policy"), dict) else {}
        lab = policy.get("lab_policy", {}) if isinstance(policy.get("lab_policy"), dict) else {}
        return {
            "public_poc_research": bool(policy.get("public_poc_research")),
            "searchsploit_allowed": bool(policy.get("searchsploit_allowed")),
            "read_poc_examples": bool(policy.get("read_poc_examples")),
            "poc_applicability_validation": bool(policy.get("poc_applicability_validation")),
            "exploit_code_generation": bool(policy.get("exploit_code_generation")),
            "poc_execution": bool(policy.get("poc_execution")),
            "credential_validation": bool(credential.get("credential_validation_allowed")),
            "credential_guessing": bool(credential.get("credential_guessing_allowed")),
            "credential_spraying": bool(credential.get("credential_spraying_allowed")),
            "hash_cracking": bool(credential.get("hash_cracking_allowed")),
            "kerberos_asrep_roast": bool(kerberos.get("asrep_roast_check_allowed")),
            "kerberos_kerberoast": bool(kerberos.get("kerberoast_check_allowed")),
            "lab_flag_collection": bool(lab.get("lab_flag_collection_allowed")),
            "htb_lab_behavior": bool(lab.get("htb_lab_behavior_allowed")),
            "reverse_shell": bool(lab.get("reverse_shell_allowed")),
        }

    def _selected_target_filter(self, target: str | None, targets: list[dict[str, Any]]) -> str | None:
        selected = str(target or "").strip()
        if not selected or selected == "*":
            return None
        handles = {self._target_handle(item) for item in targets}
        return selected if selected in handles else None

    def _filter_scope_targets(
        self,
        targets: list[dict[str, Any]],
        selected_target: str | None,
    ) -> list[dict[str, Any]]:
        if not selected_target:
            return targets
        return [item for item in targets if self._target_handle(item) == selected_target]

    def _target_id_for_handle(self, handle: str | None, targets: list[dict[str, Any]]) -> str | None:
        if not handle:
            return None
        for item in targets:
            target = item.get("target", {}) if isinstance(item.get("target"), dict) else {}
            if str(target.get("handle") or "") == handle:
                return str(target.get("id") or "") or None
        return None

    def _gpu_memory_payload(self, gpu: dict[str, Any]) -> dict[str, Any]:
        used = gpu.get("memory_used_mb")
        free = gpu.get("memory_free_mb")
        total = gpu.get("memory_total_mb")
        percent = gpu.get("memory_percent")
        try:
            percent_value = float(percent) if percent is not None else 0.0
        except (TypeError, ValueError):
            percent_value = 0.0
        used_label = "unavailable"
        free_label = "unavailable"
        if isinstance(used, (int, float)) and isinstance(total, (int, float)):
            used_label = f"{used:.0f} / {total:.0f} MB"
        if isinstance(free, (int, float)):
            free_label = f"{free:.0f} MB"
        return {
            "percent": max(0.0, min(100.0, percent_value)),
            "used_mb": used,
            "free_mb": free,
            "total_mb": total,
            "used_label": used_label,
            "free_label": free_label,
        }

    def _premium_wrapper_payload(self) -> dict[str, Any]:
        local_wrapper_available = self.runtime.worker_broker.has_runner_for(
            route=ProviderRoute.REMOTE_PREMIUM,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            role=AgentRole.CLAUDE_REVIEWER,
            runner_id="agent-chat-premium-runner",
        )
        remote_enabled = bool(self.runtime.config.autonomy.allow_remote_premium)
        if local_wrapper_available:
            status = "local wrapper"
            label = "agent_chat_api wrapper"
            detail = (
                "Claude/GPT review tasks route through agent_chat_api; wrapper-backed reviews "
                "are not blocked by the remote premium flag or daily remote budget gate."
            )
            tone = "cyan"
        elif remote_enabled:
            status = "remote enabled"
            label = "remote_premium"
            detail = "Claude/GPT review tasks use the configured remote premium route."
            tone = "green"
        else:
            status = "disabled"
            label = "remote_premium"
            detail = "Claude/GPT review tasks require either the local wrapper runner or remote premium approval."
            tone = "gray"
        return {
            "status": status,
            "label": label,
            "detail": detail,
            "tone": tone,
            "provider_route": ProviderRoute.REMOTE_PREMIUM.value,
            "task_kind": TaskKind.REVIEW_PREMIUM_ESCALATION.value,
            "agent_role": AgentRole.CLAUDE_REVIEWER.value,
            "runner_id": "agent-chat-premium-runner" if local_wrapper_available else "",
            "local_chat_wrapper": "agent_chat_api" if local_wrapper_available else "",
            "local_wrapper_available": local_wrapper_available,
            "remote_premium_flag_enabled": remote_enabled,
            "remote_premium_policy_gate_bypassed_for_wrapper": local_wrapper_available,
            "remote_premium_budget_gate_bypassed_for_wrapper": local_wrapper_available,
        }
