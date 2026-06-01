from __future__ import annotations

from primordial.core.providers.model_eval_deps import (
    Callable,
    LMStudioClient,
    OllamaClient,
)
from primordial.core.providers.model_eval_adapters import (
    _LMStudioAdapter,
    _OllamaAdapter,
    _UnifiedResponse,
)
from primordial.core.providers.model_eval_service_candidates import ModelEvalCandidatesMixin
from primordial.core.providers.model_eval_service_core import ModelEvalCoreMixin
from primordial.core.providers.model_eval_service_normalization import ModelEvalNormalizationMixin
from primordial.core.providers.model_eval_service_roles import ModelEvalRolesMixin
from primordial.core.providers.model_eval_types import (
    ModelCandidate,
    ModelEvalCase,
    ModelEvalResult,
    ModelEvalSummary,
    ModelRoleSuggestion,
)

GenerateCallable = Callable[..., object]


class ModelEvaluationService(
    ModelEvalCoreMixin,
    ModelEvalRolesMixin,
    ModelEvalCandidatesMixin,
    ModelEvalNormalizationMixin,
):
    def __init__(
        self,
        ollama: OllamaClient | None = None,
        lmstudio: LMStudioClient | None = None,
        host_metrics_sampler: Callable[[], dict[str, object]] | None = None,
        lmstudio_profile: dict[str, object] | None = None,
    ) -> None:
        self.ollama = ollama
        self.lmstudio = lmstudio
        self.host_metrics_sampler = host_metrics_sampler
        self.lmstudio_profile = lmstudio_profile or {}

__all__ = (
    "GenerateCallable",
    "ModelCandidate",
    "ModelEvalCase",
    "ModelEvalResult",
    "ModelEvalSummary",
    "ModelEvaluationService",
    "ModelRoleSuggestion",
    "_LMStudioAdapter",
    "_OllamaAdapter",
    "_UnifiedResponse",
)
