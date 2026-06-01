from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import hashlib

from primordial.labs.ctf.targets import CTFTarget


@dataclass(frozen=True, slots=True)
class MutationPlan:
    original_target_id: str
    semantic_target_id: str
    seed: str
    mutated_name: str
    hostname: str
    published_ports: tuple[dict[str, Any], ...]
    mutations: dict[str, str]


class MutationPlanner:
    @staticmethod
    def plan(*, target: CTFTarget, seed: str) -> MutationPlan:
        normalized_seed = _required(seed, "seed")
        enabled = bool(target.mutation_policy.get("enabled", False))
        requested = set(_mutation_names(target.mutation_policy.get("mutate")))
        if not enabled:
            requested = set()
        name_token = _token(target.id, normalized_seed, "name")
        host_token = _token(target.id, normalized_seed, "host")
        port_offset = _number(target.id, normalized_seed, "port", 1000, 60000)
        banner_token = _token(target.id, normalized_seed, "banner")
        return MutationPlan(
            original_target_id=target.id,
            semantic_target_id=target.id,
            seed=normalized_seed,
            mutated_name=_mutated_name(target.name, name_token, requested),
            hostname=_mutated_hostname(target.id, host_token, requested),
            published_ports=_mutated_ports(target.reset.published_ports, port_offset, requested),
            mutations=_mutations(banner_token, requested),
        )


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"MutationPlanner requires {name}")
    return text


def _mutation_names(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _token(target_id: str, seed: str, purpose: str) -> str:
    digest = hashlib.sha256(f"{target_id}:{seed}:{purpose}".encode("utf-8")).hexdigest()
    return digest[:8]


def _number(target_id: str, seed: str, purpose: str, minimum: int, maximum: int) -> int:
    digest = hashlib.sha256(f"{target_id}:{seed}:{purpose}".encode("utf-8")).hexdigest()
    span = maximum - minimum
    return minimum + (int(digest[:8], 16) % span)


def _mutated_name(name: str, token: str, requested: set[str]) -> str:
    if "target_name" not in requested:
        return name
    return f"{name} [{token}]"


def _mutated_hostname(target_id: str, token: str, requested: set[str]) -> str:
    base = target_id.replace("_", "-").lower()
    if "hostname" not in requested:
        return base
    return f"{base}-{token}"


def _mutated_ports(
    published_ports: tuple[dict[str, Any], ...],
    port_offset: int,
    requested: set[str],
) -> tuple[dict[str, Any], ...]:
    if "service_ports" not in requested:
        return tuple(dict(port) for port in published_ports)
    mutated = []
    for index, port in enumerate(published_ports):
        next_port = dict(port)
        next_port["host"] = port_offset + index
        mutated.append(next_port)
    return tuple(mutated)


def _mutations(banner_token: str, requested: set[str]) -> dict[str, str]:
    if "banner_tokens" not in requested:
        return {}
    return {"banner_token": banner_token}
