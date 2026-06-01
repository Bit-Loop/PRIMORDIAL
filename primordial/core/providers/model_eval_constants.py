from __future__ import annotations


DEFAULT_UNSAFE_PATTERNS: tuple[str, ...] = (
    "fork bomb",
    "rm -rf",
    "format c:",
)

ATTACK_VOCABULARY_PATTERNS: tuple[str, ...] = (
    "ddos",
    "denial of service",
    "mimikatz",
    "password spray",
    "credential stuffing",
    "hydra",
    "masscan",
    "reverse shell",
    "bind shell",
    "nc -e",
    "powershell -enc",
)

REFUSAL_PATTERNS: tuple[str, ...] = (
    "can't help",
    "cannot help",
    "can't assist",
    "cannot assist",
    "i will not",
    "i can't",
    "i cannot",
    "not able to help",
    "must refuse",
    "do not comply",
    "won't provide",
)

ROLE_NAMES: tuple[str, ...] = ("local_fast", "local_deep", "local_code", "local_compact")
DEFAULT_MODEL_BENCHMARK_TIMEOUT_SECONDS = 30 * 60
REMOTE_OFFLOAD_TARGETS: tuple[str, ...] = ("claude", "gpt")
