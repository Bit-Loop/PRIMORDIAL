"""CTF harness contracts."""

from primordial.labs.ctf.applicability import (
    ExploitApplicabilityResult,
    validate_vulhub_exploit_applicability,
)
from primordial.labs.ctf.benchmark import BenchmarkRun
from primordial.labs.ctf.benchmark_phase import BenchmarkPhaseControlResult, verify_benchmark_phase_controls
from primordial.labs.ctf.cicd import CICDGoatPhaseControlResult, verify_cicd_goat_phase_controls
from primordial.labs.ctf.cloudgoat import CloudGoatPhaseControlResult, verify_cloudgoat_phase_controls
from primordial.labs.ctf.closed_book import ClosedBookPackage
from primordial.labs.ctf.ctfd import FakeCTFdClient
from primordial.labs.ctf.environment import (
    EnvironmentProof,
    PhaseEnvironmentProof,
    VulhubEnvironmentProof,
    probe_phase_local_lab_environment,
    probe_local_container_environment,
    probe_vulhub_cve_environment,
    verify_phase_local_lab_environment,
    verify_local_ad_lab_environment,
    verify_local_cluster_environment,
    verify_local_container_environment,
    verify_benchmark_environment,
    verify_sandbox_cloud_environment,
)
from primordial.labs.ctf.environment_probes import (
    probe_benchmark_environment,
    probe_local_ad_lab_environment,
    probe_local_cluster_environment,
    probe_localstack_cloud_environment,
)
from primordial.labs.ctf.failures import FailureAnalysis
from primordial.labs.ctf.goad import GOADPhaseControlResult, verify_goad_phase_controls
from primordial.labs.ctf.hardcode import HardcodeFinding, HardcodeScanResult, HardcodeScanner
from primordial.labs.ctf.integrity import CTFHarnessIntegrity, CTFIntegrityResult
from primordial.labs.ctf.kubernetes import KubernetesGoatPhaseControlResult, verify_kubernetes_goat_phase_controls
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
    "BenchmarkPhaseControlResult",
    "CICDGoatPhaseControlResult",
    "CTFTarget",
    "CTFHarnessIntegrity",
    "CTFIntegrityResult",
    "CTFLabPhase",
    "CTFLabPhaseCatalog",
    "CTFPhaseTargetSet",
    "ClosedBookPackage",
    "ClosedBookPolicy",
    "CloudGoatPhaseControlResult",
    "EvidenceExpectations",
    "EnvironmentProof",
    "ExploitApplicabilityResult",
    "FailureAnalysis",
    "FakeCTFdClient",
    "GOADPhaseControlResult",
    "HardcodeFinding",
    "HardcodeScanResult",
    "HardcodeScanner",
    "KubernetesGoatPhaseControlResult",
    "MutationPlan",
    "MutationPlanner",
    "PatchProposal",
    "PhaseEnvironmentProof",
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
    "verify_benchmark_phase_controls",
    "verify_cicd_goat_phase_controls",
    "verify_cloudgoat_phase_controls",
    "verify_goad_phase_controls",
    "verify_kubernetes_goat_phase_controls",
    "load_ctf_target_manifest",
    "load_ctf_target_manifest_file",
    "load_ctf_lab_phase_catalog",
    "load_ctf_phase_target_manifests",
    "probe_phase_local_lab_environment",
    "probe_benchmark_environment",
    "probe_local_ad_lab_environment",
    "probe_local_cluster_environment",
    "probe_local_container_environment",
    "probe_localstack_cloud_environment",
    "probe_vulhub_cve_environment",
    "validate_vulhub_exploit_applicability",
    "verify_benchmark_environment",
    "verify_phase_local_lab_environment",
    "verify_local_ad_lab_environment",
    "verify_local_cluster_environment",
    "verify_local_container_environment",
    "verify_sandbox_cloud_environment",
]
