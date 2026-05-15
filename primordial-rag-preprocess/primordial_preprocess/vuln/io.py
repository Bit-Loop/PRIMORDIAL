from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel


def read_json(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON payload is not an object: {path}")
    return payload


def write_json(path: Path | str, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(_dumpable(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_jsonl(path: Path | str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    source = Path(path)
    if not source.exists():
        return rows
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"{source}:{line_number}: JSONL row is not an object")
        rows.append(payload)
    return rows


def append_jsonl(path: Path | str, records: Iterable[Any]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(_dumpable(record), sort_keys=True, ensure_ascii=False) + "\n")
            count += 1
    return count


def write_jsonl(path: Path | str, records: Iterable[Any]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(_dumpable(record), sort_keys=True, ensure_ascii=False) + "\n")
            count += 1
    return count


def _dumpable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_dumpable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _dumpable(item) for key, item in value.items()}
    return value
