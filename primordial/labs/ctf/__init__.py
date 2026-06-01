"""CTF harness contracts."""

from primordial.labs.ctf.applicability import (
    ExploitApplicabilityResult,
    validate_vulhub_exploit_applicability,
)
from primordial.labs.ctf.benchmark import BenchmarkRun
from primordial.labs.ctf.closed_book import ClosedBookPackage
from primordial.labs.ctf.ctfd import FakeCTFdClient
from primordial.labs.ctf.environment import (
    EnvironmentProof,
    VulhubEnvironmentProof,
    probe_local_container_environment,
    probe_vulhub_cve_environment,
    verify_local_container_environment,
)
from primordial.labs.ctf.failures import FailureAnalysis
from primordial.labs.ctf.hardcode import HardcodeFinding, HardcodeScanResult, HardcodeScanner
from primordial.labs.ctf.integrity import CTFHarnessIntegrity, CTFIntegrityResult
from primordial.labs.ctf.mutation import MutationPlan, MutationPlanner
from primordial.labs.ctf.patches import PatchProposal
from primordial.labs.ctf.phase_targets import CTFPhaseTargetSet, load_ctf_phase_target_manifests
from primordial.labs.ctf.phases import CTFLabPhase, CTFLabPhaseCatalog, load_ctf_lab_phase_catalog
from primordial.labs.ctf.postmortem import PostmortemRecord
from primordial.labs.ctf.scoring import (
    ScoringEvidenceResult,
    compute_scoring_summary,
    validate_scoring_results_evidence_refs,
)
from primordial.labs.ctf.sessions import SolveSession
from primordial.labs.ctf.targets import (
    CTFTarget,
    ClosedBookPolicy,
    EvidenceExpectations,
    ResetMetadata,
    TargetScope,
    VulnerabilityMetadata,
    load_ctf_target_manifest,
    load_ctf_target_manifest_file,
)
from primordial.labs.ctf.verification import SolveVerificationResult, SolveVerifier

__all__ = [
    "BenchmarkRun",
    "CTFTarget",
    "CTFHarnessIntegrity",
    "CTFIntegrityResult",
    "CTFLabPhase",
    "CTFLabPhaseCatalog",
    "CTFPhaseTargetSet",
    "ClosedBookPackage",
    "ClosedBookPolicy",
    "EvidenceExpectations",
    "EnvironmentProof",
    "ExploitApplicabilityResult",
    "FailureAnalysis",
    "FakeCTFdClient",
    "HardcodeFinding",
    "HardcodeScanResult",
    "HardcodeScanner",
    "MutationPlan",
    "MutationPlanner",
    "PatchProposal",
    "PostmortemRecord",
    "ResetMetadata",
    "ScoringEvidenceResult",
    "SolveSession",
    "SolveVerificationResult",
    "SolveVerifier",
    "TargetScope",
    "VulnerabilityMetadata",
    "VulhubEnvironmentProof",
    "compute_scoring_summary",
    "validate_scoring_results_evidence_refs",
    "load_ctf_target_manifest",
    "load_ctf_target_manifest_file",
    "load_ctf_lab_phase_catalog",
    "load_ctf_phase_target_manifests",
    "probe_local_container_environment",
    "probe_vulhub_cve_environment",
    "validate_vulhub_exploit_applicability",
    "verify_local_container_environment",
]
