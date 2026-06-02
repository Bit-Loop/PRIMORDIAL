from __future__ import annotations

from dataclasses import dataclass
import re

from primordial.labs.ctf.targets import CTFTarget


FLAG_PATTERN = re.compile(r"\b(?:(?i:flag|ctf)|(?:[A-Z][A-Z0-9_-]{1,31}-\d+))\{[^}\s]{4,}\}")
DEFAULT_STRIP_MARKERS = (
    "expected_flag",
    "expected_flags",
    "hidden_flag",
    "hidden_flags",
    "generated-postmortem",
    "postmortem",
    "prior-solve",
    "prior_solve",
    "solution",
    "solutions",
    "test-split",
    "test_split",
    "writeup",
    "writeups",
)


@dataclass(frozen=True, slots=True)
class ClosedBookPackage:
    target_id: str
    agent_paths: tuple[str, ...]
    operator_only_paths: tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        target: CTFTarget,
        candidate_paths: list[str] | tuple[str, ...],
    ) -> ClosedBookPackage:
        target_id = _required(target.id, "target_id")
        strip_prefixes = _normalize_prefixes(target.closed_book.strip_paths)
        agent_paths: list[str] = []
        operator_only_paths: list[str] = []
        for path in _path_tuple(candidate_paths):
            if FLAG_PATTERN.search(path):
                raise ValueError("ClosedBookPackage agent candidate paths must not include raw flag material")
            if _is_operator_only(path, strip_prefixes):
                operator_only_paths.append(path)
            else:
                agent_paths.append(path)
        return cls(
            target_id=target_id,
            agent_paths=tuple(agent_paths),
            operator_only_paths=tuple(operator_only_paths),
        )


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"ClosedBookPackage requires {name}")
    return text


def _path_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_package_path(item) for item in value if str(item).strip())


def _package_path(value: object) -> str:
    path = str(value).strip().replace("\\", "/")
    if path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
        raise ValueError("ClosedBookPackage candidate paths must be archive-relative")
    parts = tuple(part for part in path.split("/") if part)
    if any(part in {".", ".."} for part in parts):
        raise ValueError("ClosedBookPackage candidate paths must not contain traversal components")
    return "/".join(parts)


def _normalize_prefixes(value: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(path.strip().lstrip("/").rstrip("/") + "/" for path in value if path.strip())


def _is_operator_only(path: str, strip_prefixes: tuple[str, ...]) -> bool:
    normalized = path.lower()
    if any(normalized.startswith(prefix.lower()) for prefix in strip_prefixes):
        return True
    parts = tuple(part for part in re.split(r"[/._-]+", normalized) if part)
    return any(marker in parts or marker in normalized for marker in DEFAULT_STRIP_MARKERS)
