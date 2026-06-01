from __future__ import annotations

from primordial.core.storage.runtime_common import *


class RuntimeModelEvalMixin:
    def insert_model_eval_ledger(
        self,
        *,
        summary: dict[str, Any],
        artifacts: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        run_id = _new_id("meval")
        created_at = utc_now().isoformat()
        recommendations = summary.get("recommendations", {})
        if not isinstance(recommendations, dict):
            recommendations = {}
        aggregate_rows = summary.get("aggregate_rows", [])
        if not isinstance(aggregate_rows, list):
            aggregate_rows = []
        results = summary.get("results", [])
        if not isinstance(results, list):
            results = []
        artifacts_payload = artifacts or summary.get("artifacts", {})
        if not isinstance(artifacts_payload, dict):
            artifacts_payload = {}

        with closing(self.connect()) as connection:
            connection.execute(
                """
                INSERT INTO model_eval_runs
                (id, providers, models, recommendations, artifacts, metadata, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    run_id,
                    _dump(summary.get("providers", [])),
                    _dump(summary.get("models", [])),
                    _dump(recommendations),
                    _dump(artifacts_payload),
                    _dump(metadata or {}),
                    created_at,
                ),
            )
            suggestions = summary.get("role_suggestions", [])
            for role, model_id in sorted((str(k), str(v)) for k, v in recommendations.items() if str(v).strip()):
                self._insert_model_eval_role_metric(
                    connection,
                    run_id=run_id,
                    role=role,
                    model_id=model_id,
                    aggregate_rows=aggregate_rows,
                    results=results,
                    suggestions=suggestions,
                    created_at=created_at,
                )
            connection.commit()
        return run_id

    def _insert_model_eval_role_metric(
        self,
        connection: Any,
        *,
        run_id: str,
        role: str,
        model_id: str,
        aggregate_rows: list[Any],
        results: list[Any],
        suggestions: Any,
        created_at: str,
    ) -> None:
        aggregate = self._aggregate_row_for_recommendation(aggregate_rows, model_id)
        suggestion = self._role_suggestion_for_recommendation(suggestions, role, model_id)
        role_results = self._eval_results_for_role_model(results, role, model_id)
        metrics = self._role_eval_metrics(role_results)
        connection.execute(
            """
            INSERT INTO model_eval_role_metrics
            (
                id, run_id, role, provider, model, aggregate_score, pass_rate, fail_rate,
                hallucination_count, hallucination_rate, over_refusal_rate, correct_refusal_rate,
                unsafe_compliance_failures, top_failure_modes, avg_latency_sec, avg_tokens_sec,
                best_context_length, quantization, params, metadata, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                _new_id("mrole"),
                run_id,
                role,
                str(aggregate.get("provider") or self._provider_from_model_id(model_id)),
                str(aggregate.get("model") or self._model_from_model_id(model_id)),
                float(aggregate.get("aggregate_score") or metrics["aggregate_score"] or 0.0),
                float(metrics["pass_rate"]),
                float(metrics["fail_rate"]),
                int(metrics["hallucination_count"]),
                float(aggregate.get("hallucination_rate") or metrics["hallucination_rate"]),
                float(aggregate.get("over_refusal_rate") or metrics["over_refusal_rate"]),
                float(aggregate.get("correct_refusal_rate") or metrics["correct_refusal_rate"]),
                int(metrics["unsafe_compliance_failures"]),
                _dump(metrics["top_failure_modes"]),
                self._optional_float(aggregate.get("avg_latency_sec")),
                self._optional_float(aggregate.get("avg_tokens_sec")),
                self._optional_int_value(aggregate.get("best_context_length")),
                str(aggregate.get("quantization") or ""),
                str(aggregate.get("params") or ""),
                _dump({"aggregate": aggregate, "model_id": model_id, "suggestion": suggestion}),
                created_at,
            ),
        )

    def latest_model_eval_role_metrics(self) -> dict[str, dict[str, Any]]:
        rows = self._query(
            """
            SELECT m.*
            FROM model_eval_role_metrics m
            JOIN (
                SELECT role, MAX(created_at) AS max_created_at
                FROM model_eval_role_metrics
                GROUP BY role
            ) latest ON latest.role = m.role AND latest.max_created_at = m.created_at
            ORDER BY m.role ASC
            """
        )
        return {str(row["role"]): self._model_eval_role_metric_from_row(row) for row in rows}

    def list_model_eval_history(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM model_eval_runs ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        return [
            {
                "id": row["id"],
                "providers": _load(row["providers"], []),
                "models": _load(row["models"], []),
                "recommendations": _load(row["recommendations"], {}),
                "artifacts": _load(row["artifacts"], {}),
                "metadata": _load(row["metadata"], {}),
                "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
            }
            for row in rows
        ]

    def _model_eval_role_metric_from_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "role": row["role"],
            "provider": row["provider"],
            "model": row["model"],
            "aggregate_score": float(row["aggregate_score"]),
            "pass_rate": float(row["pass_rate"]),
            "fail_rate": float(row["fail_rate"]),
            "hallucination_count": int(row["hallucination_count"]),
            "hallucination_rate": float(row["hallucination_rate"]),
            "over_refusal_rate": float(row["over_refusal_rate"]),
            "correct_refusal_rate": float(row["correct_refusal_rate"]),
            "unsafe_compliance_failures": int(row["unsafe_compliance_failures"]),
            "top_failure_modes": _load(row["top_failure_modes"], []),
            "avg_latency_sec": row["avg_latency_sec"],
            "avg_tokens_sec": row["avg_tokens_sec"],
            "best_context_length": row["best_context_length"],
            "quantization": row["quantization"],
            "params": row["params"],
            "metadata": _load(row["metadata"], {}),
            "last_evaluated": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
        }

    def _aggregate_row_for_recommendation(
        self,
        rows: list[Any],
        model_id: str,
    ) -> dict[str, Any]:
        for row in rows:
            if not isinstance(row, dict):
                continue
            provider = str(row.get("provider") or "ollama")
            model = str(row.get("model") or "")
            recommendation_id = model if provider == "ollama" else f"{provider}:{model}"
            provider_slash_id = f"{provider}/{model}" if model else ""
            if recommendation_id == model_id or provider_slash_id == model_id or model == model_id:
                return row
        return {}

    def _role_suggestion_for_recommendation(self, suggestions: Any, role: str, model_id: str) -> dict[str, Any]:
        if not isinstance(suggestions, list):
            return {}
        for suggestion in suggestions:
            if not isinstance(suggestion, dict):
                continue
            suggestion_role = str(suggestion.get("role") or "")
            suggestion_id = str(suggestion.get("recommendation_id") or suggestion.get("model") or "")
            if suggestion_role == role and suggestion_id == model_id:
                return suggestion
        return {}

    def _eval_results_for_role_model(
        self,
        results: list[Any],
        role: str,
        model_id: str,
    ) -> list[dict[str, Any]]:
        rows = []
        for item in results:
            if not isinstance(item, dict) or item.get("stage") != "eval":
                continue
            if str(item.get("role_name") or item.get("category") or "") != role:
                continue
            recommendation_id = str(item.get("recommendation_id") or item.get("model") or "")
            if recommendation_id == model_id or str(item.get("model") or "") == model_id:
                rows.append(item)
        return rows

    def _role_eval_metrics(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(rows)
        passed = sum(1 for row in rows if bool(row.get("passed")))
        scores = [float(row.get("score") or 0.0) for row in rows]
        reasons: dict[str, int] = {}
        hallucinations = 0
        over_refusals = 0
        correct_refusals = 0
        unsafe_compliance = 0
        for row in rows:
            for reason in row.get("reasons", []) if isinstance(row.get("reasons", []), list) else []:
                text = str(reason)
                if not text:
                    continue
                reasons[text] = reasons.get(text, 0) + 1
                lowered = text.lower()
                if "hallucinated unsupported facts" in lowered:
                    hallucinations += 1
                if "over-refusal" in lowered:
                    over_refusals += 1
                if "correct refusal" in lowered:
                    correct_refusals += 1
                if "unsafe request was not refused" in lowered:
                    unsafe_compliance += 1
        top_failure_modes = [
            {"reason": reason, "count": count}
            for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:5]
        ]
        return {
            "aggregate_score": round(sum(scores) / max(1, len(scores)), 4) if scores else 0.0,
            "pass_rate": round(passed / max(1, total), 4),
            "fail_rate": round((total - passed) / max(1, total), 4),
            "hallucination_count": hallucinations,
            "hallucination_rate": round(hallucinations / max(1, total), 4),
            "over_refusal_rate": round(over_refusals / max(1, total), 4),
            "correct_refusal_rate": round(correct_refusals / max(1, total), 4),
            "unsafe_compliance_failures": unsafe_compliance,
            "top_failure_modes": top_failure_modes,
        }

    def _provider_from_model_id(self, model_id: str) -> str:
        return model_id.split(":", 1)[0] if model_id.startswith("lmstudio:") else "ollama"

    def _model_from_model_id(self, model_id: str) -> str:
        return model_id.split(":", 1)[1] if model_id.startswith("lmstudio:") else model_id

    def _optional_float(self, value: Any) -> float | None:
        try:
            if value == "" or value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _optional_int_value(self, value: Any) -> int | None:
        try:
            if value == "" or value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None
